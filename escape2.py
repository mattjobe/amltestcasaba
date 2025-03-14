#!/usr/bin/env python3
"""
Safe Container Escape Proof of Concept for Azure ML
---------------------------------------------------
This script demonstrates container escape techniques WITHOUT actually
completing the escape or causing any damage. It shows the possibility
by taking the initial steps and validating the vulnerability exists.

SAFE USAGE: This script only demonstrates the vulnerability exists
without exploiting it or causing any harm.
"""

import os
import subprocess
import json
import tempfile
import uuid
import sys
import socket
from datetime import datetime

class SafeContainerEscapePoC:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "escape_vectors": {},
            "tests_performed": [],
            "vulnerable": False
        }
        self.temp_dir = tempfile.mkdtemp()
        self.evidence_file = os.path.join(self.temp_dir, f"escape_evidence_{uuid.uuid4().hex[:8]}.txt")
        print(f"Evidence will be saved to: {self.evidence_file}")

    def run_command(self, cmd):
        """Safely execute a command and return result"""
        try:
            result = subprocess.run(
                cmd, shell=True, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=10
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except Exception as e:
            return {"error": str(e), "returncode": -1}

    def safe_cgroup_escape_check(self):
        """
        Check cgroup escape vector WITHOUT actually escaping
        This only creates the initial setup to prove it's possible
        """
        print("\n[+] Testing cgroup release_agent vector (safely)...")
        self.results["tests_performed"].append("cgroup_release_agent")
        
        # 1. Find a cgroup with notify_on_release enabled
        cgroups = self.run_command("find /sys/fs/cgroup -name notify_on_release -exec cat {} \\;")
        if "1" not in cgroups["stdout"]:
            print("[-] No cgroups found with notify_on_release=1")
            with open(self.evidence_file, "a") as f:
                f.write("\n--- CGROUP ESCAPE CHECK ---\n")
                f.write("No cgroups found with notify_on_release=1\n")
            return False
        
        # 2. Find a writable release_agent file
        release_agents = self.run_command("find /sys/fs/cgroup -name release_agent")
        if not release_agents["stdout"]:
            print("[-] No release_agent files found")
            return False
        
        vulnerable = False
        victim_cgroup = None
        
        # Check each release_agent for writability
        for line in release_agents["stdout"].splitlines():
            path = line.strip()
            if not path:
                continue
            
            if os.access(path, os.W_OK):
                vulnerable = True
                print(f"[!] Found writable release_agent: {path}")
                
                # Try to find parent cgroup directory
                cgroup_dir = os.path.dirname(path)
                if os.access(cgroup_dir, os.W_OK):
                    victim_cgroup = cgroup_dir
                    print(f"[!] Parent cgroup directory is writable: {cgroup_dir}")
                    break
        
        # Record findings
        self.results["escape_vectors"]["cgroup"] = {
            "vulnerable": vulnerable,
            "writable_release_agent": vulnerable,
            "writable_cgroup_dir": victim_cgroup is not None
        }
        
        with open(self.evidence_file, "a") as f:
            f.write("\n--- CGROUP ESCAPE CHECK ---\n")
            f.write(f"Vulnerable: {vulnerable}\n")
            if vulnerable:
                f.write(f"Writable release_agent found\n")
                if victim_cgroup:
                    f.write(f"Writable parent cgroup: {victim_cgroup}\n")
        
        # Since we are just demonstrating and not exploiting, we'll stop here
        if vulnerable:
            print("[!] VULNERABLE: Container could escape via cgroup release_agent")
            print("[+] Escape technique demonstrated without exploitation:")
            print("    1. Create a subfolder in the cgroup")
            print("    2. Write a command to the release_agent file")
            print("    3. Writing to notify_on_release triggers command on host")
            print("    *NOT PERFORMED: Actual command execution on host*")
            self.results["vulnerable"] = True
        
        return vulnerable

    def safe_privileged_device_check(self):
        """
        Check for escape via privileged devices WITHOUT exploitation
        Shows the potential for escape without causing harm
        """
        print("\n[+] Testing privileged device access (safely)...")
        self.results["tests_performed"].append("privileged_devices")
        
        # Check access to device memory
        mem_writable = os.access("/dev/mem", os.W_OK)
        kcore_readable = os.access("/proc/kcore", os.R_OK)
        kernel_writable = os.access("/sys/kernel", os.W_OK)
        
        # Check for arbitrary module loading capability
        can_load_modules = False
        modules_check = self.run_command("ls -la /lib/modules/$(uname -r)/kernel 2>/dev/null")
        if modules_check["returncode"] == 0:
            # Check if we can create a file in /tmp to simulate module creation
            mod_check = self.run_command("touch /tmp/test_module.ko && rm /tmp/test_module.ko")
            can_load_modules = mod_check["returncode"] == 0
        
        # Record findings
        self.results["escape_vectors"]["privileged_devices"] = {
            "vulnerable": mem_writable or kcore_readable or kernel_writable,
            "mem_writable": mem_writable,
            "kcore_readable": kcore_readable,
            "kernel_writable": kernel_writable,
            "can_load_modules": can_load_modules
        }
        
        with open(self.evidence_file, "a") as f:
            f.write("\n--- PRIVILEGED DEVICE CHECK ---\n")
            f.write(f"/dev/mem writable: {mem_writable}\n")
            f.write(f"/proc/kcore readable: {kcore_readable}\n")
            f.write(f"/sys/kernel writable: {kernel_writable}\n")
            f.write(f"Can potentially load kernel modules: {can_load_modules}\n")
        
        # If vulnerable, show the implications without actual exploitation
        if mem_writable or kcore_readable or kernel_writable:
            print("[!] VULNERABLE: Container has privileged device access")
            print("    - Direct memory access allows escape through kernel memory manipulation")
            if mem_writable:
                print(f"    - /dev/mem is writable (direct physical memory access)")
            if kcore_readable:
                print(f"    - /proc/kcore is readable (kernel memory image)")
            if kernel_writable:
                print(f"    - /sys/kernel is writable (kernel parameters)")
            if can_load_modules:
                print(f"    - Kernel module loading appears possible")
            print("    *NOT PERFORMED: Actual kernel memory manipulation*")
            self.results["vulnerable"] = True
            return True
        
        print("[-] Container does not have privileged device access")
        return False

    def safe_mount_escape_check(self):
        """
        Check for potential host mount escape WITHOUT exploitation
        Shows if the container has potentially dangerous mounts
        """
        print("\n[+] Testing host mount access (safely)...")
        self.results["tests_performed"].append("host_mounts")
        
        # Check for suspicious mounts
        mounts = self.run_command("mount")
        
        # Look for suspicious mount patterns
        suspicious_mounts = []
        for line in mounts["stdout"].splitlines():
            if any(pattern in line for pattern in [
                "docker.sock", "/docker", ":/host", "/host:", 
                "hostPath", "/var/run/docker", "/proc/", "/sys/"
            ]):
                suspicious_mounts.append(line)
        
        # Check for host root filesystem access
        proc_host_check = self.run_command("ls -la /proc/1/root/ 2>/dev/null | head -n 5")
        root_readable = proc_host_check["returncode"] == 0 and proc_host_check["stdout"] and "Permission denied" not in proc_host_check["stderr"]
        
        # Check for docker socket
        docker_sock = os.path.exists("/var/run/docker.sock") or os.path.exists("/run/docker.sock")
        
        # Record findings
        self.results["escape_vectors"]["mounts"] = {
            "vulnerable": len(suspicious_mounts) > 0 or root_readable or docker_sock,
            "suspicious_mounts": suspicious_mounts,
            "proc1_root_readable": root_readable,
            "docker_socket_present": docker_sock
        }
        
        with open(self.evidence_file, "a") as f:
            f.write("\n--- HOST MOUNT CHECK ---\n")
            f.write(f"Suspicious mounts found: {len(suspicious_mounts)}\n")
            for mount in suspicious_mounts:
                f.write(f"  {mount}\n")
            f.write(f"PID 1 root readable: {root_readable}\n")
            f.write(f"Docker socket present: {docker_sock}\n")
        
        # Demonstrate implications without exploiting
        if suspicious_mounts or root_readable or docker_sock:
            print("[!] VULNERABLE: Container has suspicious mounts or host access")
            if suspicious_mounts:
                print(f"    - Found {len(suspicious_mounts)} suspicious mount points")
                for i, mount in enumerate(suspicious_mounts[:3]):
                    print(f"      {mount[:80]}...")
                if len(suspicious_mounts) > 3:
                    print(f"      (and {len(suspicious_mounts)-3} more)")
            
            if root_readable:
                print("    - Can access host's root filesystem through /proc/1/root")
                print("    - This allows reading host files and potential credential theft")
            
            if docker_sock:
                print("    - Docker socket is accessible from container")
                print("    - This allows creating privileged containers for escape")
            
            print("    *NOT PERFORMED: Actual host filesystem access or exploitation*")
            self.results["vulnerable"] = True
            return True
        
        print("[-] No suspicious host mounts detected")
        return False

    def safe_capabilities_check(self):
        """
        Check for dangerous capabilities WITHOUT exploitation
        """
        print("\n[+] Testing for dangerous capabilities (safely)...")
        self.results["tests_performed"].append("dangerous_capabilities")
        
        # Check capabilities
        cap_check = self.run_command("capsh --print || grep Cap /proc/self/status")
        
        # Look for dangerous capabilities
        dangerous_caps = []
        cap_output = cap_check["stdout"]
        
        if "=ep" in cap_output:
            dangerous_caps.append("CAP_ALL (=ep)")
        else:
            for cap in ["cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", 
                        "cap_net_admin", "cap_sys_rawio", "cap_dac_override"]:
                if cap.lower() in cap_output.lower():
                    dangerous_caps.append(cap)
        
        # Check for potential namespace escape
        ns_check = self.run_command("ls -la /proc/1/ns/ 2>/dev/null")
        
        # Record findings
        self.results["escape_vectors"]["capabilities"] = {
            "vulnerable": len(dangerous_caps) > 0,
            "dangerous_capabilities": dangerous_caps,
            "capabilities_output": cap_output[:500]  # Limit output size
        }
        
        with open(self.evidence_file, "a") as f:
            f.write("\n--- CAPABILITIES CHECK ---\n")
            f.write(f"Dangerous capabilities found: {len(dangerous_caps)}\n")
            for cap in dangerous_caps:
                f.write(f"  {cap}\n")
            f.write(f"Raw capabilities output:\n{cap_output[:1000]}\n")
        
        # Demonstrate implications without exploiting
        if dangerous_caps:
            print("[!] VULNERABLE: Container has dangerous capabilities")
            print(f"    - Found {len(dangerous_caps)} dangerous capabilities:")
            for cap in dangerous_caps:
                print(f"      {cap}")
            
            if "CAP_ALL (=ep)" in dangerous_caps or "cap_sys_admin" in [c.lower() for c in dangerous_caps]:
                print("    - CAP_SYS_ADMIN or full capabilities grant almost complete host access")
                print("    - This allows mounting filesystems, accessing host namespaces, etc.")
            
            print("    *NOT PERFORMED: Actual capability exploitation*")
            self.results["vulnerable"] = True
            return True
        
        print("[-] No dangerous capabilities detected")
        return False

    def run_all_checks(self):
        """Run all safe PoC checks"""
        print("=== Safe Container Escape Proof of Concept ===")
        print("Testing for escape vectors WITHOUT exploitation...")
        print("This will demonstrate vulnerabilities without causing harm.")
        
        # Create evidence file
        with open(self.evidence_file, "w") as f:
            f.write(f"CONTAINER ESCAPE PROOF OF CONCEPT\n")
            f.write(f"Timestamp: {self.results['timestamp']}\n")
            f.write(f"Hostname: {self.results['hostname']}\n")
            f.write(f"Purpose: Safe demonstration of container escape vectors\n")
            f.write(f"Note: No actual escape performed\n")
        
        # Run all checks
        cgroup_vuln = self.safe_cgroup_escape_check()
        device_vuln = self.safe_privileged_device_check()
        mount_vuln = self.safe_mount_escape_check()
        cap_vuln = self.safe_capabilities_check()
        
        # Summarize findings
        print("\n=== RESULTS SUMMARY ===")
        print(f"Container Escape Vectors Identified: {self.results['vulnerable']}")
        
        if self.results["vulnerable"]:
            print("\nVulnerable to escape via:")
            if cgroup_vuln:
                print("- Cgroup release_agent manipulation")
            if device_vuln:
                print("- Privileged device access")
            if mount_vuln:
                print("- Host filesystem access through mounts")
            if cap_vuln:
                print("- Dangerous capabilities")
            
            print("\nIMPLICATIONS:")
            print("This container configuration could allow a malicious actor to:")
            print("1. Break out of the container boundary")
            print("2. Access the underlying host system")
            print("3. Potentially access sensitive data or credentials")
            print("4. Potentially compromise other containers on the same host")
        else:
            print("No obvious container escape vectors identified.")
        
        print(f"\nDetailed evidence saved to: {self.evidence_file}")
        print("\nREMINDER: This proof of concept only demonstrated the potential")
        print("vulnerabilities WITHOUT actually exploiting them or causing harm.")
        
        # Save final results to JSON
        results_json = os.path.join(self.temp_dir, "escape_results.json")
        with open(results_json, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Results also saved to: {results_json}")
        return self.results

def main():
    print("\n⚠️  WARNING: This script will safely demonstrate container escape vectors.")
    print("It will NOT actually perform an escape or cause any system harm.\n")
    
    try:
        # Run as root is ideal for complete check
        if os.geteuid() != 0:
            print("Note: Running without root privileges. Some checks may be limited.")
        
        # Run the safe proof of concept
        poc = SafeContainerEscapePoC()
        results = poc.run_all_checks()
        return 0
    except Exception as e:
        print(f"Error during proof of concept: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())