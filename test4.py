#!/usr/bin/env python3
"""
Quick Azure ML Container Escape Verification Script

A simplified version that focuses on critical tests and completes quickly.
"""

import os
import sys
import uuid
import json
import socket
import datetime
import subprocess
import time

class QuickEscapeVerifier:
    def __init__(self):
        self.run_id = str(uuid.uuid4())[:8]
        self.results = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": socket.gethostname(),
            "tests": {},
            "conclusion": None
        }
    
    def _run_command(self, cmd, shell=False, timeout=5):
        """Run a command with a strict timeout."""
        try:
            if isinstance(cmd, str) and not shell:
                cmd = cmd.split()
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                shell=shell,
                timeout=timeout
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "success": False
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }
    
    def test_marker_file(self):
        """Test if we can create and verify marker files."""
        print("[*] Testing with marker files...")
        
        # Create normal marker
        normal_marker = f"/tmp/normal-marker-{self.run_id}"
        normal_content = f"Normal marker: {self.run_id}"
        
        try:
            with open(normal_marker, "w") as f:
                f.write(normal_content)
            normal_created = True
        except:
            normal_created = False
        
        # Try to create "host" marker through chroot
        host_marker = f"/tmp/host-marker-{self.run_id}"
        host_content = f"Host marker: {self.run_id}"
        
        chroot_cmd = f"chroot /proc/1/root /bin/sh -c \"echo '{host_content}' > {host_marker}\""
        chroot_result = self._run_command(chroot_cmd, shell=True)
        
        # Check if we can read both markers
        normal_readable = False
        if os.path.exists(normal_marker):
            try:
                with open(normal_marker, "r") as f:
                    normal_read = f.read().strip()
                normal_readable = normal_read == normal_content
            except:
                pass
                
        host_readable = False
        if os.path.exists(host_marker):
            try:
                with open(host_marker, "r") as f:
                    host_read = f.read().strip()
                host_readable = host_read == host_content
            except:
                pass
        
        # Try to read the normal marker using chroot
        chroot_read_cmd = f"chroot /proc/1/root cat {normal_marker}"
        chroot_read = self._run_command(chroot_read_cmd, shell=True)
        cross_readable = chroot_read["success"] and chroot_read["stdout"].strip() == normal_content
        
        # Clean up
        try:
            if os.path.exists(normal_marker):
                os.unlink(normal_marker)
            if os.path.exists(host_marker):
                os.unlink(host_marker)
        except:
            pass
            
        result = {
            "normal_marker": {
                "path": normal_marker,
                "created": normal_created,
                "readable": normal_readable
            },
            "host_marker": {
                "path": host_marker,
                "created": chroot_result["success"],
                "readable": host_readable
            },
            "cross_context": {
                "normal_from_chroot": cross_readable
            },
            "analysis": {
                "same_view": normal_readable and host_readable and cross_readable
            }
        }
        
        self.results["tests"]["marker_test"] = result
        return result
    
    def test_filesystem_access(self):
        """Test access to sensitive host files."""
        print("[*] Testing filesystem access...")
        
        sensitive_files = [
            "/etc/shadow",
            "/etc/sudoers",
            "/var/lib/docker",
            "/root/.ssh",
            "/var/run/docker.sock"
        ]
        
        file_access = {}
        for path in sensitive_files:
            if os.path.exists(path):
                try:
                    if os.path.isdir(path):
                        entries = os.listdir(path)
                        file_access[path] = {
                            "exists": True,
                            "is_dir": True,
                            "readable": True,
                            "entries": entries[:5] if entries else []
                        }
                    else:
                        with open(path, "r") as f:
                            content = f.read(100)
                        file_access[path] = {
                            "exists": True,
                            "is_dir": False,
                            "readable": True,
                            "content_sample": content[:50] if content else ""
                        }
                except:
                    file_access[path] = {
                        "exists": True,
                        "readable": False
                    }
            else:
                file_access[path] = {
                    "exists": False,
                    "readable": False
                }
        
        # Test /proc/1/root access
        proc1_accessible = os.access("/proc/1/root", os.R_OK)
        proc1_listable = False
        proc1_contents = []
        
        if proc1_accessible:
            try:
                proc1_contents = os.listdir("/proc/1/root")
                proc1_listable = len(proc1_contents) > 0
            except:
                pass
                
        file_access["/proc/1/root"] = {
            "exists": os.path.exists("/proc/1/root"),
            "accessible": proc1_accessible,
            "listable": proc1_listable,
            "content_sample": proc1_contents[:5] if proc1_listable else []
        }
        
        self.results["tests"]["filesystem_access"] = file_access
        return file_access
    
    def test_network_interfaces(self):
        """Test network interface visibility."""
        print("[*] Testing network interfaces...")
        
        # Get interfaces
        ip_addr = self._run_command("ip addr")
        
        # Check for container runtime sockets
        runtime_sockets = [
            "/var/run/docker.sock",
            "/run/containerd/containerd.sock",
            "/var/run/crio/crio.sock"
        ]
        
        socket_access = {}
        for sock in runtime_sockets:
            socket_access[sock] = {
                "exists": os.path.exists(sock)
            }
            
            if socket_access[sock]["exists"] and sock == "/var/run/docker.sock":
                cmd = "curl -s --unix-socket /var/run/docker.sock http://localhost/info"
                result = self._run_command(cmd, shell=True)
                socket_access[sock]["accessible"] = result["success"]
        
        # Check for common host-only interfaces
        host_interfaces = ["docker0", "veth", "cni", "flannel", "calico"]
        found_interfaces = []
        
        if ip_addr["success"]:
            for iface in host_interfaces:
                if iface in ip_addr["stdout"]:
                    found_interfaces.append(iface)
                    
        result = {
            "container_runtime_sockets": socket_access,
            "host_interfaces": found_interfaces,
            "raw_interfaces": ip_addr["stdout"][:500] if ip_addr["success"] else "Failed to get interfaces"
        }
        
        self.results["tests"]["network_interfaces"] = result
        return result
    
    def test_cgroup_comparison(self):
        """Compare cgroups between contexts."""
        print("[*] Testing cgroup comparison...")
        
        # Get our cgroups
        self_cgroups = self._run_command("cat /proc/self/cgroup")
        
        # Get host cgroups via chroot
        host_cgroups = self._run_command("chroot /proc/1/root cat /proc/1/cgroup", shell=True)
        
        # Check for container markers in cgroups
        container_markers = ["docker", "container", "pod", ".scope"]
        found_markers = []
        
        if self_cgroups["success"]:
            for marker in container_markers:
                if marker in self_cgroups["stdout"]:
                    found_markers.append(marker)
        
        result = {
            "container_markers": found_markers,
            "cgroups_match": (self_cgroups["success"] and host_cgroups["success"] and 
                             self_cgroups["stdout"] == host_cgroups["stdout"]),
            "self_cgroups": self_cgroups["stdout"] if self_cgroups["success"] else "Failed to get cgroups",
            "host_cgroups": host_cgroups["stdout"] if host_cgroups["success"] else "Failed to get host cgroups"
        }
        
        self.results["tests"]["cgroup_comparison"] = result
        return result
    
    def test_process_tree(self):
        """Test process tree visibility."""
        print("[*] Testing process tree...")
        
        # Get all processes
        ps_result = self._run_command("ps -ef")
        
        # Get init process (PID 1)
        init_cmd = self._run_command("cat /proc/1/cmdline")
        init_name = init_cmd["stdout"].replace("\x00", " ").strip() if init_cmd["success"] else "Unknown"
        
        # Check for containerization indicators
        container_processes = ["containerd", "dockerd", "kubelet"]
        found_indicators = []
        
        if ps_result["success"]:
            for proc in container_processes:
                if proc in ps_result["stdout"]:
                    found_indicators.append(proc)
        
        # Count processes - containers typically have fewer
        proc_count = len(ps_result["stdout"].splitlines()) - 1 if ps_result["success"] else 0
        
        result = {
            "init_process": init_name,
            "process_count": proc_count,
            "container_indicators": found_indicators,
            "likely_host_init": any(x in init_name for x in ["systemd", "init"])
        }
        
        self.results["tests"]["process_tree"] = result
        return result
    
    def analyze_results(self):
        """Analyze all test results and draw conclusions."""
        print("[*] Analyzing results...")
        
        conclusion = {
            "appears_escaped": None,
            "confidence": 0,
            "evidence": [],
            "likely_explanation": ""
        }
        
        # Evidence from marker test
        if "marker_test" in self.results["tests"]:
            test = self.results["tests"]["marker_test"]
            
            if test["analysis"]["same_view"]:
                conclusion["evidence"].append({
                    "type": "against_escape",
                    "detail": "Marker files visible identically in both contexts, suggesting single namespace"
                })
            elif test["host_marker"]["created"] and test["host_marker"]["readable"]:
                conclusion["evidence"].append({
                    "type": "for_escape",
                    "detail": "Successfully created marker file via chroot"
                })
        
        # Evidence from filesystem access
        if "filesystem_access" in self.results["tests"]:
            test = self.results["tests"]["filesystem_access"]
            
            sensitive_read = False
            for path, details in test.items():
                if path != "/proc/1/root" and details.get("readable"):
                    sensitive_read = True
                    conclusion["evidence"].append({
                        "type": "for_escape",
                        "detail": f"Can read sensitive file: {path}"
                    })
                    
            if test.get("/proc/1/root", {}).get("listable"):
                conclusion["evidence"].append({
                    "type": "for_escape",
                    "detail": "Can list contents of /proc/1/root"
                })
        
        # Evidence from network interfaces
        if "network_interfaces" in self.results["tests"]:
            test = self.results["tests"]["network_interfaces"]
            
            if test["host_interfaces"]:
                conclusion["evidence"].append({
                    "type": "for_escape",
                    "detail": f"Can see host network interfaces: {', '.join(test['host_interfaces'])}"
                })
                
            for sock, details in test["container_runtime_sockets"].items():
                if details.get("exists") and details.get("accessible", False):
                    conclusion["evidence"].append({
                        "type": "for_escape",
                        "detail": f"Can access container runtime socket: {sock}"
                    })
        
        # Evidence from cgroup comparison
        if "cgroup_comparison" in self.results["tests"]:
            test = self.results["tests"]["cgroup_comparison"]
            
            if test["cgroups_match"]:
                conclusion["evidence"].append({
                    "type": "against_escape",
                    "detail": "Cgroups match between contexts, suggesting single namespace"
                })
        
        # Evidence from process tree
        if "process_tree" in self.results["tests"]:
            test = self.results["tests"]["process_tree"]
            
            if test["likely_host_init"]:
                conclusion["evidence"].append({
                    "type": "for_escape",
                    "detail": f"PID 1 appears to be host init process: {test['init_process']}"
                })
            
            if test["process_count"] > 50:
                conclusion["evidence"].append({
                    "type": "for_escape",
                    "detail": f"High process count ({test['process_count']}) suggests host process visibility"
                })
        
        # Calculate conclusion
        for_escape = sum(1 for e in conclusion["evidence"] if e["type"] == "for_escape")
        against_escape = sum(1 for e in conclusion["evidence"] if e["type"] == "against_escape")
        
        if for_escape > against_escape:
            conclusion["appears_escaped"] = True
            conclusion["confidence"] = min(100, int(for_escape / (for_escape + against_escape) * 100))
            conclusion["likely_explanation"] = "Container escape appears successful with shared namespace access"
        elif against_escape > for_escape:
            conclusion["appears_escaped"] = False
            conclusion["confidence"] = min(100, int(against_escape / (for_escape + against_escape) * 100))
            conclusion["likely_explanation"] = "Still contained within isolation boundaries"
        else:
            conclusion["appears_escaped"] = None
            conclusion["confidence"] = 50
            conclusion["likely_explanation"] = "Inconclusive - insufficient evidence to determine status"
            
        self.results["conclusion"] = conclusion
        return conclusion
    
    def run_all_tests(self):
        """Run all tests and return results."""
        print("\n=== Quick Azure ML Container Escape Verification ===\n")
        
        self.test_marker_file()
        self.test_filesystem_access()
        self.test_network_interfaces()
        self.test_cgroup_comparison()
        self.test_process_tree()
        
        conclusion = self.analyze_results()
        
        print("\n=== Results ===")
        print(f"Status: {'LIKELY ESCAPED' if conclusion['appears_escaped'] else 'CONTAINED' if conclusion['appears_escaped'] is False else 'INCONCLUSIVE'}")
        print(f"Confidence: {conclusion['confidence']}%")
        print(f"Explanation: {conclusion['likely_explanation']}")
        
        print("\nEvidence:")
        for evidence in conclusion["evidence"]:
            marker = "+" if evidence["type"] == "for_escape" else "-"
            print(f" {marker} {evidence['detail']}")
            
        return self.results
    
    def save_results(self, output_file=None):
        """Save results to a JSON file."""
        if output_file is None:
            output_file = f"quick_escape_results_{socket.gethostname()}_{self.run_id}.json"
            
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
            
        print(f"\nResults saved to {output_file}")
        return output_file


if __name__ == "__main__":
    try:
        verifier = QuickEscapeVerifier()
        results = verifier.run_all_tests()
        output_file = verifier.save_results()
        print("Verification complete!")
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during testing: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
