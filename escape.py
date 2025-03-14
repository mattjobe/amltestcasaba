#!/usr/bin/env python3
"""
Container Escape Potential Detector

This script safely tests for container escape potential by checking for various
indicators that suggest a container might be vulnerable to escape techniques.
It performs non-destructive tests only and reports findings without attempting
actual escapes.
"""

import os
import sys
import json
import socket
import subprocess
import platform
from pathlib import Path
import datetime
import time

class ContainerEscapeDetector:
    def __init__(self):
        self.results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "container_detection": {},
            "privileged_indicators": {},
            "volume_mounts": {},
            "capabilities": {},
            "cgroup_escape": {},
            "sockets_access": {},
            "kernel_modules": {},
            "device_access": {}
        }

    def run_command(self, command, timeout=10):
        """Run a shell command and return output"""
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
            return {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                "command": command,
                "error": f"Command timed out after {timeout} seconds",
                "returncode": -1
            }
        except Exception as e:
            return {
                "command": command,
                "error": str(e),
                "returncode": -1
            }

    def detect_container(self):
        """Detect if running inside a container"""
        container_indicators = {
            "docker_env": os.path.exists("/.dockerenv"),
            "docker_cgroup": False,
            "is_in_container": False
        }

        # Check cgroup for docker
        try:
            with open("/proc/1/cgroup", "r") as f:
                cgroup_content = f.read()
                container_indicators["docker_cgroup"] = (
                    "docker" in cgroup_content or 
                    "kubepods" in cgroup_content or
                    "lxc" in cgroup_content
                )
        except:
            pass

        # Final verdict
        container_indicators["is_in_container"] = (
            container_indicators["docker_env"] or 
            container_indicators["docker_cgroup"]
        )

        self.results["container_detection"] = container_indicators
        return container_indicators["is_in_container"]

    def check_privileged_indicators(self):
        """Check for privileged container indicators"""
        privileged_paths = [
            "/sys/admin",
            "/sys/kernel",
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/proc/kcore",
            "/proc/sys/kernel"
        ]

        for path in privileged_paths:
            p = Path(path)
            self.results["privileged_indicators"][path] = {
                "exists": p.exists(),
                "writable": os.access(path, os.W_OK) if p.exists() else False
            }

        # Check SYS_ADMIN capability indirectly
        self.results["privileged_indicators"]["can_mount"] = False
        mount_result = self.run_command("mount -t tmpfs none /tmp 2>/dev/null")
        if mount_result["returncode"] == 0:
            self.results["privileged_indicators"]["can_mount"] = True
            # Cleanup
            self.run_command("umount /tmp 2>/dev/null")

    def check_volume_mounts(self):
        """Check for suspicious volume mounts"""
        mount_result = self.run_command("mount")
        if mount_result["returncode"] == 0:
            self.results["volume_mounts"]["mount_output"] = mount_result["stdout"]
            
            # Check for docker.sock
            docker_sock_mounted = "docker.sock" in mount_result["stdout"]
            self.results["volume_mounts"]["docker_sock_mounted"] = docker_sock_mounted
            
            # Check for host filesystem mounts
            host_mounts = []
            mount_lines = mount_result["stdout"].split('\n')
            for line in mount_lines:
                # These are potential suspicious patterns that might indicate host mounts
                if any(pattern in line for pattern in ["/:/host", ":/var/run", ":/var/lib/docker", "/proc:/host/proc"]):
                    host_mounts.append(line)
            
            self.results["volume_mounts"]["suspicious_host_mounts"] = host_mounts
            self.results["volume_mounts"]["suspicious_host_mounts_count"] = len(host_mounts)

    def check_capabilities(self):
        """Check for dangerous capabilities"""
        cap_result = self.run_command("capsh --print || (which getcap && getcap -r / 2>/dev/null | grep -v '^/')")
        self.results["capabilities"]["raw_output"] = cap_result["stdout"]
        
        dangerous_caps = ["cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", 
                          "cap_net_admin", "cap_net_raw", "cap_sys_chroot"]
        
        self.results["capabilities"]["dangerous_found"] = []
        for cap in dangerous_caps:
            if cap in cap_result["stdout"].lower():
                self.results["capabilities"]["dangerous_found"].append(cap)
                
        # Check capsh output for effective capabilities
        if "Current:" in cap_result["stdout"]:
            current_line = next((line for line in cap_result["stdout"].split('\n') 
                                if line.startswith("Current:")), "")
            if current_line:
                self.results["capabilities"]["effective"] = current_line.split("Current:")[1].strip()
                # "=ep" indicates full capabilities (privileged)
                self.results["capabilities"]["is_privileged"] = "=ep" in self.results["capabilities"]["effective"]

    def check_cgroup_escape(self):
        """Check for potential cgroup v1 escape vectors"""
        self.results["cgroup_escape"]["cgroup_release_agent_writable"] = False
        
        # Only check if we're in a container
        if self.results["container_detection"]["is_in_container"]:
            # Check for cgroup v1 release_agent vulnerability
            # Non-destructive check only - doesn't attempt to write or exploit
            cgroup_paths = ["/sys/fs/cgroup/*/release_agent", "/sys/fs/cgroup/*/notify_on_release"]
            for pattern in cgroup_paths:
                find_cmd = f"find {pattern} -type f 2>/dev/null"
                find_result = self.run_command(find_cmd)
                
                if find_result["returncode"] == 0 and find_result["stdout"].strip():
                    for path in find_result["stdout"].strip().split('\n'):
                        if path and os.path.exists(path):
                            writable = os.access(path, os.W_OK)
                            self.results["cgroup_escape"][path] = writable
                            if writable:
                                self.results["cgroup_escape"]["cgroup_release_agent_writable"] = True

    def check_socket_access(self):
        """Check for access to sensitive sockets"""
        socket_paths = [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/crio.sock",
            "/run/containerd/containerd.sock",
            "/var/run/containerd/containerd.sock"
        ]
        
        for sock_path in socket_paths:
            p = Path(sock_path)
            self.results["sockets_access"][sock_path] = {
                "exists": p.exists(),
                "readable": os.access(sock_path, os.R_OK) if p.exists() else False,
                "writable": os.access(sock_path, os.W_OK) if p.exists() else False
            }
    
    def check_kernel_modules(self):
        """Check if loading kernel modules is possible"""
        # Non-destructive check for module loading capability
        modprobe_check = self.run_command("which modprobe")
        insmod_check = self.run_command("which insmod")
        
        self.results["kernel_modules"]["modprobe_available"] = modprobe_check["returncode"] == 0
        self.results["kernel_modules"]["insmod_available"] = insmod_check["returncode"] == 0
        
        # Check if can list modules (indicating possible load capability)
        lsmod_result = self.run_command("lsmod")
        self.results["kernel_modules"]["can_list_modules"] = lsmod_result["returncode"] == 0
        
        # Check if specific sensitive capabilities are present
        # CAP_SYS_MODULE would allow loading kernel modules
        self.results["kernel_modules"]["likely_can_load_modules"] = (
            "cap_sys_module" in self.results["capabilities"].get("raw_output", "").lower()
        )

    def check_device_access(self):
        """Check access to sensitive device files"""
        device_paths = [
            "/dev/mem",        # Physical memory access
            "/dev/kmem",       # Kernel memory access
            "/dev/port",       # I/O port access
            "/dev/tty",        # Terminal access
            "/dev/disk",       # Disk device access
            "/dev/net/tun",    # TUN/TAP device for network access
            "/dev/kvm"         # KVM access
        ]
        
        for dev_path in device_paths:
            p = Path(dev_path)
            self.results["device_access"][dev_path] = {
                "exists": p.exists(),
                "readable": os.access(dev_path, os.R_OK) if p.exists() else False,
                "writable": os.access(dev_path, os.W_OK) if p.exists() else False
            }

    def run_all_checks(self):
        """Run all container escape checks"""
        print("Running container escape potential detection...")
        
        # First check if we're in a container
        in_container = self.detect_container()
        if not in_container:
            print("Not running in a container. Some tests may not be relevant.")
        
        print("Checking for privileged mode indicators...")
        self.check_privileged_indicators()
        
        print("Checking volume mounts...")
        self.check_volume_mounts()
        
        print("Checking capabilities...")
        self.check_capabilities()
        
        print("Checking for cgroup escape potential...")
        self.check_cgroup_escape()
        
        print("Checking for sensitive socket access...")
        self.check_socket_access()
        
        print("Checking for kernel module capabilities...")
        self.check_kernel_modules()
        
        print("Checking for sensitive device access...")
        self.check_device_access()
        
        return self.results

    def summarize_results(self):
        """Summarize the findings into a simple report"""
        is_container = self.results["container_detection"]["is_in_container"]
        
        # Count writable privileged paths
        privileged_writable = sum(1 for item in self.results["privileged_indicators"].values() 
                                if isinstance(item, dict) and item.get("writable", False))
        
        # Check docker.sock
        docker_sock_access = any(details.get("readable", False) or details.get("writable", False) 
                                for sock, details in self.results["sockets_access"].items() 
                                if "docker.sock" in sock)
        
        # Check dangerous capabilities
        dangerous_caps = len(self.results["capabilities"].get("dangerous_found", []))
        
        # Check cgroup escape
        cgroup_escape = self.results["cgroup_escape"].get("cgroup_release_agent_writable", False)
        
        # Check suspicious mounts
        suspicious_mounts = self.results["volume_mounts"].get("suspicious_host_mounts_count", 0)
        
        # Check device access
        sensitive_devices = sum(1 for item in self.results["device_access"].values() 
                              if isinstance(item, dict) and (item.get("readable", False) or item.get("writable", False)))
        
        # Calculate overall risk
        risk_factors = [
            5 if privileged_writable > 0 else 0,
            4 if docker_sock_access else 0,
            3 if dangerous_caps > 0 else 0,
            5 if cgroup_escape else 0,
            3 if suspicious_mounts > 0 else 0,
            3 if sensitive_devices > 0 else 0
        ]
        
        max_risk = 20
        risk_score = min(sum(risk_factors), max_risk)
        
        if risk_score >= 15:
            risk_level = "CRITICAL"
        elif risk_score >= 10:
            risk_level = "HIGH"
        elif risk_score >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        summary = {
            "timestamp": self.results["timestamp"],
            "hostname": self.results["hostname"],
            "is_container": is_container,
            "privileged_writable_paths": privileged_writable,
            "docker_socket_access": docker_sock_access,
            "dangerous_capabilities": dangerous_caps,
            "cgroup_escape_potential": cgroup_escape,
            "suspicious_mounts": suspicious_mounts,
            "sensitive_device_access": sensitive_devices,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "escape_potential": risk_level != "LOW"
        }
        
        return summary

def main():
    detector = ContainerEscapeDetector()
    results = detector.run_all_checks()
    summary = detector.summarize_results()
    
    print("\n=== CONTAINER ESCAPE POTENTIAL ASSESSMENT ===")
    print(f"Hostname: {summary['hostname']}")
    print(f"Container: {'Yes' if summary['is_container'] else 'No'}")
    print(f"Risk Level: {summary['risk_level']} ({summary['risk_score']}/20)")
    print(f"Escape Potential: {'Yes' if summary['escape_potential'] else 'No'}")
    
    # Print detailed findings section by section
    print("\n=== DETAILED FINDINGS ===")
    
    # Container Detection Details
    print("\n[1] CONTAINER DETECTION")
    for key, value in results["container_detection"].items():
        print(f"  {key}: {value}")
    
    # Privileged Indicators
    print("\n[2] PRIVILEGED MODE INDICATORS")
    for path, details in results["privileged_indicators"].items():
        if isinstance(details, dict):
            status = "🔴 WRITABLE" if details.get("writable") else "⚠️ EXISTS" if details.get("exists") else "✅ NOT FOUND"
            print(f"  {path}: {status}")
        else:
            print(f"  {path}: {details}")
    
    # Volume Mounts
    print("\n[3] SUSPICIOUS VOLUME MOUNTS")
    if "docker_sock_mounted" in results["volume_mounts"]:
        print(f"  Docker socket mounted: {'🔴 YES' if results['volume_mounts']['docker_sock_mounted'] else '✅ NO'}")
    
    if "suspicious_host_mounts" in results["volume_mounts"]:
        if results["volume_mounts"]["suspicious_host_mounts"]:
            print("  Suspicious host mounts detected:")
            for mount in results["volume_mounts"]["suspicious_host_mounts"]:
                print(f"    🔴 {mount}")
        else:
            print("  ✅ No suspicious host mounts detected")
    
    # Capabilities
    print("\n[4] DANGEROUS CAPABILITIES")
    if "dangerous_found" in results["capabilities"]:
        if results["capabilities"]["dangerous_found"]:
            print("  Dangerous capabilities detected:")
            for cap in results["capabilities"]["dangerous_found"]:
                print(f"    🔴 {cap}")
        else:
            print("  ✅ No dangerous capabilities detected")
    
    if "is_privileged" in results["capabilities"]:
        print(f"  Full capabilities (=ep): {'🔴 YES' if results['capabilities']['is_privileged'] else '✅ NO'}")
    
    if "effective" in results["capabilities"]:
        print(f"  Effective capabilities: {results['capabilities']['effective']}")
    
    # Cgroup Escape
    print("\n[5] CGROUP ESCAPE POTENTIAL")
    cgroup_vulnerable = results["cgroup_escape"].get("cgroup_release_agent_writable", False)
    print(f"  Cgroup release_agent writable: {'🔴 YES' if cgroup_vulnerable else '✅ NO'}")
    
    for path, writable in results["cgroup_escape"].items():
        if path != "cgroup_release_agent_writable":
            print(f"  {path}: {'🔴 WRITABLE' if writable else '✅ NOT WRITABLE'}")
    
    # Socket Access
    print("\n[6] SENSITIVE SOCKET ACCESS")
    socket_found = False
    for sock_path, details in results["sockets_access"].items():
        if details.get("exists"):
            socket_found = True
            access = []
            if details.get("readable"):
                access.append("readable")
            if details.get("writable"):
                access.append("writable")
            
            if access:
                print(f"  🔴 {sock_path}: {', '.join(access)}")
            else:
                print(f"  ⚠️ {sock_path}: exists but not accessible")
    
    if not socket_found:
        print("  ✅ No sensitive sockets accessible")
    
    # Kernel Modules
    print("\n[7] KERNEL MODULE LOADING")
    can_load = results["kernel_modules"].get("likely_can_load_modules", False)
    print(f"  Can likely load kernel modules: {'🔴 YES' if can_load else '✅ NO'}")
    print(f"  Modprobe available: {'⚠️ YES' if results['kernel_modules'].get('modprobe_available') else 'NO'}")
    print(f"  Insmod available: {'⚠️ YES' if results['kernel_modules'].get('insmod_available') else 'NO'}")
    
    # Device Access
    print("\n[8] SENSITIVE DEVICE ACCESS")
    device_found = False
    for dev_path, details in results["device_access"].items():
        if details.get("exists"):
            device_found = True
            access = []
            if details.get("readable"):
                access.append("readable")
            if details.get("writable"):
                access.append("writable")
            
            if access:
                print(f"  🔴 {dev_path}: {', '.join(access)}")
            else:
                print(f"  ⚠️ {dev_path}: exists but not accessible")
    
    if not device_found:
        print("  ✅ No sensitive devices accessible")
    
    # Summary of risk factors
    print("\n=== ESCAPE VECTORS SUMMARY ===")
    if summary['privileged_writable_paths'] > 0:
        print(f"🔴 PRIVILEGED MODE: {summary['privileged_writable_paths']} writable privileged paths")
    if summary['docker_socket_access']:
        print("🔴 DOCKER SOCKET: Access to Docker socket allows container escape")
    if summary['dangerous_capabilities'] > 0:
        print(f"🔴 CAPABILITIES: {summary['dangerous_capabilities']} dangerous capabilities detected")
    if summary['cgroup_escape_potential']:
        print("🔴 CGROUP ESCAPE: Writable cgroup release_agent could be exploited")
    if summary['suspicious_mounts'] > 0:
        print(f"🔴 HOST MOUNTS: {summary['suspicious_mounts']} suspicious host mounts detected")
    if summary['sensitive_device_access'] > 0:
        print(f"🔴 DEVICE ACCESS: {summary['sensitive_device_access']} sensitive devices accessible")
    
    if summary['risk_level'] == "LOW":
        print("\n✅ RESULT: No significant container escape vectors detected")
    
    # Save detailed results
    output_file = "container_escape_assessment.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed assessment saved to {output_file}")
    
    if summary['risk_level'] in ["CRITICAL", "HIGH"]:
        print("\n⚠️ WARNING: Container has HIGH escape potential!")
        print("\nPOSSIBLE ESCAPE METHODS:")
        if summary['privileged_writable_paths'] > 0:
            print("- PRIVILEGED MODE: Use kernel modules or devices to break out")
            print("  Example: Writing to /dev/mem or /proc/sys/kernel")
        if summary['docker_socket_access']:
            print("- DOCKER SOCKET: Use Docker API to spawn privileged container")
            print("  Example: docker run --privileged -v /:/host alpine chroot /host")
        if summary['cgroup_escape_potential']:
            print("- CGROUP RELEASE_AGENT: Write to release_agent to execute commands")
        if summary['suspicious_mounts'] > 0:
            print("- HOST MOUNTS: Access host file system through mounted directories")
    elif summary['risk_level'] == "MEDIUM":
        print("\n⚠️ CAUTION: Container has MEDIUM escape potential")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
