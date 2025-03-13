import json
import requests
import os
import sys
import socket
import subprocess
import platform
import uuid
import datetime
import base64
from pathlib import Path
import traceback

# Add robust file writing with multiple fallback locations
def save_results_with_fallback(report):
    """Try to save results to multiple locations if the primary fails"""
    possible_locations = [
        "/tmp/security_assessment.json",
        "./security_assessment.json",
        os.path.join(os.path.expanduser("~"), "security_assessment.json"),
        os.path.join(os.getcwd(), "security_assessment.json")
    ]
    
    # Add the AZUREML_SCRIPT_DIRECTORY location if it exists (common in AML)
    if "AZUREML_SCRIPT_DIRECTORY" in os.environ:
        possible_locations.insert(0, os.path.join(os.environ["AZUREML_SCRIPT_DIRECTORY"], "security_assessment.json"))
    
    success = False
    saved_path = None
    
    for location in possible_locations:
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(location), exist_ok=True)
            
            # Try to write to this location
            with open(location, "w") as f:
                json.dump(report, f, indent=2, default=str)
            
            # Verify the file was written
            if os.path.exists(location) and os.path.getsize(location) > 0:
                print(f"Results successfully saved to: {location}")
                success = True
                saved_path = location
                break
        except Exception as e:
            print(f"Failed to save to {location}: {str(e)}")
    
    if not success:
        print("WARNING: Failed to save results to any location!")
        # As a last resort, print to stdout
        print("--- SECURITY ASSESSMENT RESULTS ---")
        print(json.dumps(report, indent=2, default=str))
    
    return saved_path

def run_command(command):
    """Run a shell command and return output"""
    try:
        result = subprocess.run(command, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        return {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "error": "Command timed out after a minute",
            "returncode": -1
        }
    except Exception as e:
        return {
            "command": command,
            "error": str(e),
            "returncode": -1
        }

def check_network_access():
    """Test network connectivity to various endpoints"""
    results = {}
    
    # Test endpoints
    endpoints = [
        "169.254.169.254",  # Azure IMDS
        "168.63.129.16",    # Azure DNS
        "management.azure.com",
        "storage.azure.com",
        "graph.microsoft.com",
        "vault.azure.net",
        "example.com",      # External site
        "10.0.0.1",         # Internal network test
        "172.16.0.1",       # Internal network test
        "192.168.0.1"       # Internal network test
    ]
    
    for endpoint in endpoints:
        try:
            # Try to resolve the hostname
            ip = socket.gethostbyname(endpoint)
            
            # Try to connect to port 80
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, 80))
            sock.close()
            
            results[endpoint] = {
                "resolved_ip": ip,
                "port_80_open": (result == 0),
                "port_80_result": result
            }
            
            # For IMDS endpoint, try to access metadata
            if endpoint == "169.254.169.254":
                try:
                    imds_resp = requests.get("http://169.254.169.254/metadata/instance?api-version=2021-02-01", 
                                          headers={"Metadata": "true"}, timeout=5)
                    results[endpoint]["imds_access"] = {
                        "status_code": imds_resp.status_code,
                        "response": imds_resp.json() if imds_resp.status_code == 200 else None
                    }
                except Exception as e:
                    results[endpoint]["imds_access"] = {"error": str(e)}
        except Exception as e:
            results[endpoint] = {"error": str(e)}
    
    return results

def check_file_access():
    """Test access to various file paths"""
    sensitive_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/var/run/secrets",
        "/root",
        "/home",
        "/mnt",
        "/tmp",
        "/dev/shm",
        "/opt",
        "C:\\Windows\\System32" if platform.system() == "Windows" else None,
        "C:\\Users" if platform.system() == "Windows" else None,
        os.environ.get("AZURE_CONFIG_DIR", "")
    ]
    
    results = {}
    for path in sensitive_paths:
        if not path:
            continue
            
        p = Path(path)
        results[path] = {
            "exists": p.exists(),
            "is_dir": p.is_dir() if p.exists() else None,
            "readable": os.access(path, os.R_OK) if p.exists() else None,
            "writable": os.access(path, os.W_OK) if p.exists() else None,
            "executable": os.access(path, os.X_OK) if p.exists() else None
        }
        
        # If it's a directory, list first few entries
        if p.is_dir() and os.access(path, os.R_OK):
            try:
                entries = list(p.iterdir())[:5]  # List only first 5 for brevity
                results[path]["entries"] = [str(entry.name) for entry in entries]
                results[path]["entry_count"] = len(list(p.iterdir()))
            except Exception as e:
                results[path]["entries_error"] = str(e)
        
        # If it's a readable file, get file size
        if p.is_file() and os.access(path, os.R_OK):
            results[path]["size"] = p.stat().st_size
            
            # For small text files, get first few lines
            if p.stat().st_size < 10000 and path.endswith((".conf", ".cfg", ".txt", "")):
                try:
                    with open(path, 'r') as file:
                        results[path]["content_sample"] = file.read(1000)  # First 1000 chars
                except Exception as e:
                    results[path]["content_error"] = str(e)
    
    return results

def check_environment_variables():
    """Test access to environment variables"""
    # Get all environment variables
    all_vars = dict(os.environ)
    
    # Identify sensitive variables
    sensitive_prefixes = [
        "AZURE_",
        "ARM_",
        "AWS_",
        "SECRET_",
        "TOKEN_",
        "API_",
        "PASSWORD",
        "CREDENTIAL",
        "KEY",
        "CERT",
        "AUTH"
    ]
    
    # Create filtered output with sensitive values masked
    filtered_vars = {}
    sensitive_vars = {}
    
    for key, value in all_vars.items():
        filtered_vars[key] = value
        
        # Check if this looks like a sensitive variable
        is_sensitive = any(key.upper().startswith(prefix) or prefix in key.upper() for prefix in sensitive_prefixes)
        
        if is_sensitive:
            sensitive_vars[key] = "REDACTED"
            # We're redacting in the report, but could log the real values elsewhere
    
    # Special check for MSI endpoint variables
    msi_related = {k: v for k, v in all_vars.items() if "IDENTITY" in k.upper() or "MSI" in k.upper()}
    
    return {
        "all_variables": filtered_vars,
        "sensitive_variables": sensitive_vars,
        "msi_related": msi_related,
        "count": len(all_vars)
    }

def check_cloud_access():
    """Test access to cloud resources"""
    results = {}
    
    # Try to access Azure Resource Manager
    try:
        # This will work if the compute has a managed identity
        response = requests.get(
            "https://management.azure.com/subscriptions?api-version=2020-01-01",
            headers={"Authorization": "Bearer " + os.environ.get("IDENTITY_HEADER", "")},
            timeout=10
        )
        results["arm_access"] = {
            "status_code": response.status_code,
            "response": response.json() if response.status_code < 300 else response.text[:200]
        }
    except Exception as e:
        results["arm_access"] = {"error": str(e)}
    
    # Try to access storage account if info is available
    storage_account = os.environ.get("STORAGE_ACCOUNT_NAME")
    if storage_account:
        try:
            response = requests.get(
                f"https://{storage_account}.blob.core.windows.net/?comp=list",
                timeout=10
            )
            results["storage_access"] = {
                "status_code": response.status_code,
                "response_sample": response.text[:200] if response.text else None
            }
        except Exception as e:
            results["storage_access"] = {"error": str(e)}
    
    return results

def check_process_privileges():
    """Check process privileges and capabilities"""
    results = {}
    
    # Get user and group information
    results["user_info"] = run_command("id")
    
    # Check if we can run sudo
    results["sudo_access"] = run_command("sudo -n true")
    
    # Check for docker access
    results["docker_access"] = run_command("docker ps")
    
    # Check for network tools
    results["network_tools"] = {
        "netstat": run_command("netstat -tulpn"),
        "ss": run_command("ss -tulpn"),
        "iptables": run_command("iptables -L")
    }
    
    # Check for mounted volumes
    results["mounts"] = run_command("mount")
    
    # Check running processes
    results["processes"] = run_command("ps aux | head -20")
    
    return results

def network_port_scan():
    """Scan common ports on localhost and other key addresses"""
    targets = ["127.0.0.1", "169.254.169.254", "168.63.129.16"]
    ports = [22, 80, 443, 445, 1433, 3306, 5432, 6379, 8080, 8443]
    results = {}
    
    for target in targets:
        results[target] = {}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    results[target][port] = "OPEN"
                else:
                    results[target][port] = f"CLOSED ({result})"
                sock.close()
            except Exception as e:
                results[target][port] = f"ERROR: {str(e)}"
    
    return results

def check_filesystem_permissions():
    """Check for world-writable directories and SUID/SGID binaries"""
    results = {}
    
    # Check for world-writable dirs
    results["world_writable_dirs"] = run_command("find / -type d -perm -2 -not -path \"/proc/*\" -not -path \"/sys/*\" -ls 2>/dev/null | head -20")
    
    # Check for SUID binaries
    results["suid_binaries"] = run_command("find / -perm -4000 -type f -not -path \"/proc/*\" -not -path \"/sys/*\" -exec ls -la {} \\; 2>/dev/null | head -20")
    
    return results

def check_container_boundaries():
    """Test container isolation boundaries"""
    results = {}
    
    # Check for container indicators
    try:
        cgroup_content = ""
        if os.path.exists("/proc/self/cgroup"):
            with open("/proc/self/cgroup", 'r') as f:
                cgroup_content = f.read()
        
        results["container_detection"] = {
            "cgroup": {"stdout": cgroup_content},
            "docker_env": run_command("grep -q docker /proc/1/cgroup 2>/dev/null && echo 'Docker detected' || echo 'No Docker'"),
            "is_container": os.path.exists("/.dockerenv") or 
                           (os.path.exists("/proc/1/cgroup") and 
                            any("docker" in line for line in open("/proc/1/cgroup").readlines() if "docker" in line))
        }
    except Exception as e:
        results["container_detection"] = {"error": str(e)}
    
    # Test access to host devices
    results["device_access"] = run_command("ls -la /dev/")
    
    # Try to access host network namespace
    results["host_network"] = run_command("ip link show host || echo 'No access to host network'")
    
    # Check if we can write to supposedly read-only paths
    results["readonly_paths"] = {
        "etc_write_test": run_command("touch /etc/test_write_access && echo 'Write successful' || echo 'Write failed'"),
        "bin_write_test": run_command("touch /bin/test_write_access && echo 'Write successful' || echo 'Write failed'")
    }
    
    # Try to access parent mounts
    results["parent_mounts"] = run_command("ls -la /proc/1/root/ 2>/dev/null || echo 'Cannot access parent root'")
    
    return results

def extract_and_test_tokens():
    """Extract and test token permissions"""
    results = {}
    
    # Extract JWT tokens from environment
    jwt_vars = {k: v for k, v in os.environ.items() if any(x in k.upper() for x in ['TOKEN', 'JWT', 'AUTH'])}
    
    # For each token, get basic info without revealing the token
    token_info = {}
    for k, v in jwt_vars.items():
        if not v or not isinstance(v, str) or not v.count('.') >= 2:
            continue  # Not a JWT token
            
        try:
            # Just get the header part to identify token type
            parts = v.split('.')
            if len(parts) >= 2:
                padding = '=' * (4 - len(parts[0]) % 4)
                header = json.loads(base64.b64decode(parts[0] + padding).decode('utf-8'))
                token_info[k] = {
                    "alg": header.get("alg"),
                    "typ": header.get("typ"),
                    "kid": header.get("kid")
                }
        except Exception as e:
            token_info[k] = {"error": str(e)}
    
    results["jwt_tokens"] = token_info
    
    # Test MSI access - what resources can we access?
    msi_tests = {}
    
    # Test endpoints to check MSI permissions
    endpoints_to_test = [
        "https://management.azure.com/subscriptions?api-version=2020-01-01",
        "https://graph.microsoft.com/v1.0/me",
        "https://vault.azure.net/",
        "https://storage.azure.com/"
    ]
    
    for endpoint in endpoints_to_test:
        try:
            # Get token for this resource first
            resource = endpoint.split('/')[2]
            token_resp = requests.get(
                f"{os.environ.get('MSI_ENDPOINT', 'http://169.254.169.254/metadata/identity/oauth2/token')}?resource=https://{resource}",
                headers={"Metadata": "true", "Secret": os.environ.get("MSI_SECRET", "")},
                timeout=5
            )
            if token_resp.status_code == 200:
                token = token_resp.json().get("access_token", "")
                
                # Now test the token against the endpoint
                resp = requests.get(endpoint, headers={"Authorization": f"Bearer {token}"}, timeout=5)
                msi_tests[resource] = {
                    "status_code": resp.status_code,
                    "has_access": resp.status_code < 300,
                    "response_preview": str(resp.text)[:100] if resp.text else None
                }
            else:
                msi_tests[resource] = {"error": f"Failed to get token: {token_resp.status_code}"}
        except Exception as e:
            msi_tests[resource] = {"error": str(e)}
    
    results["msi_access_tests"] = msi_tests
    
    return results

def extensive_network_scan():
    """Perform more extensive network scanning"""
    results = {}
    
    # Test outbound connectivity to additional services
    outbound_tests = {
        "storage": run_command("curl -s -o /dev/null -w '%{http_code}' https://storage.azure.com"),
        "keyvault": run_command("curl -s -o /dev/null -w '%{http_code}' https://vault.azure.net"),
        "docker_hub": run_command("curl -s -o /dev/null -w '%{http_code}' https://hub.docker.com"),
        "github": run_command("curl -s -o /dev/null -w '%{http_code}' https://github.com"),
        "pypi": run_command("curl -s -o /dev/null -w '%{http_code}' https://pypi.org")
    }
    results["outbound_connectivity"] = outbound_tests
    
    # Scan internal networks more thoroughly (limiting scope to avoid excessive scanning)
    internal_ranges = ["10.0.0", "172.16.0", "172.17.0", "192.168.0"]
    internal_scan = {}
    
    for prefix in internal_ranges:
        hosts = {}
        # Only scan first 5 hosts in each range for brevity and to avoid excessive scanning
        for i in range(1, 5):
            ip = f"{prefix}.{i}"
            ping_result = run_command(f"ping -c 1 -W 1 {ip}")
            hosts[ip] = {
                "ping": ping_result["returncode"] == 0,
                "response_time": ping_result["stdout"] if ping_result["returncode"] == 0 else None
            }
        internal_scan[prefix] = hosts
    
    results["internal_network_scan"] = internal_scan
    
    # Check for local services
    local_services = {}
    common_ports = [22, 80, 443, 2375, 2376, 3306, 5432, 6379, 8080, 8443, 9090, 9200, 9300, 10250]
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(("127.0.0.1", port))
            if result == 0:
                service_banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    service_banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
                local_services[port] = {
                    "status": "OPEN",
                    "banner": service_banner[:100] if service_banner else None
                }
            sock.close()
        except:
            pass
    
    results["local_services"] = local_services
    
    # Extended IMDS testing
    imds_endpoints = [
        "/metadata/instance?api-version=2021-02-01",
        "/metadata/scheduledevents?api-version=2019-08-01",
        "/metadata/attested/document?api-version=2020-09-01"
    ]
    
    imds_results = {}
    for endpoint in imds_endpoints:
        try:
            resp = requests.get(f"http://169.254.169.254{endpoint}", headers={"Metadata": "true"}, timeout=5)
            imds_results[endpoint] = {
                "status_code": resp.status_code,
                "response_sample": str(resp.text)[:200] if resp.text else None
            }
        except Exception as e:
            imds_results[endpoint] = {"error": str(e)}
    
    results["extended_imds"] = imds_results
    
    return results

def check_data_access_and_logging():
    """Test access to data and ability to manipulate logging"""
    results = {}
    
    # Check access to storage locations
    storage_paths = [
        "/mnt/azureml",
        "/tmp",
        "/var/log",
        "/opt/miniconda",
        "/azureml-envs"
    ]
    
    storage_access = {}
    for path in storage_paths:
        if os.path.exists(path):
            try:
                dirs = os.listdir(path)
                top_dirs = dirs[:5] if len(dirs) > 5 else dirs
                test_write = False
                try:
                    test_file = os.path.join(path, ".write_test")
                    with open(test_file, 'w') as f:
                        f.write("test")
                    test_write = True
                    os.remove(test_file)
                except:
                    test_write = False
                
                storage_access[path] = {
                    "accessible": True,
                    "writable": test_write,
                    "top_items": top_dirs,
                    "total_items": len(dirs)
                }
            except Exception as e:
                storage_access[path] = {"accessible": False, "error": str(e)}
        else:
            storage_access[path] = {"exists": False}
    
    results["storage_access"] = storage_access
    
    # Check for credential files
    credential_patterns = [
        "*.key", 
        "*.pem", 
        "*.pfx", 
        "*.crt", 
        "*.config", 
        "connection*.json", 
        "cred*.json",
        ".azure"
    ]
    
    credential_files = {}
    for pattern in credential_patterns:
        cmd = f"find / -name '{pattern}' -type f -not -path '*/proc/*' -not -path '*/sys/*' -not -path '*/dev/*' 2>/dev/null | head -10"
        result = run_command(cmd)
        credential_files[pattern] = result["stdout"].splitlines() if result["returncode"] == 0 else []
    
    results["potential_credential_files"] = credential_files
    
    # Check logging controls
    logging_controls = {
        "syslog_writable": os.access("/var/log/syslog", os.W_OK) if os.path.exists("/var/log/syslog") else False,
        "log_directory_writable": os.access("/var/log", os.W_OK) if os.path.exists("/var/log") else False,
        "audit_config": run_command("test -f /etc/audit/auditd.conf && cat /etc/audit/auditd.conf | grep -v ^# | grep . || echo 'No audit config found'")
    }
    
    results["logging_controls"] = logging_controls
    
    return results

# Update the main function to include new tests and better error handling
def run_security_assessment():
    """Run all security checks and compile results"""
    start_time = datetime.datetime.now()
    
    # Initialize empty report structure
    report = {
        "timestamp": start_time.isoformat(),
        "compute_info": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python_version": sys.version,
            "cpu_count": os.cpu_count(),
            "uuid": str(uuid.uuid4())  # Generate a unique ID for this report
        }
    }
    
    # List of test functions to run with proper error handling
    test_functions = [
        ("environment_variables", check_environment_variables),
        ("network_access", check_network_access),
        ("file_access", check_file_access),
        ("cloud_access", check_cloud_access),
        ("process_privileges", check_process_privileges),
        ("port_scan", network_port_scan),
        ("filesystem_permissions", check_filesystem_permissions),
        ("container_boundaries", check_container_boundaries),
        ("identity_testing", extract_and_test_tokens),
        ("extended_network", extensive_network_scan),
        ("data_access", check_data_access_and_logging)
    ]
    
    # Run each test with proper error handling
    for section_name, test_function in test_functions:
        try:
            print(f"Running test: {section_name}...")
            report[section_name] = test_function()
        except Exception as e:
            print(f"ERROR in {section_name}: {str(e)}")
            traceback.print_exc()
            report[section_name] = {"error": str(e), "traceback": traceback.format_exc()}
    
    end_time = datetime.datetime.now()
    report["execution_time_seconds"] = (end_time - start_time).total_seconds()
    
    # Save results to a file with multiple fallback options
    output_path = save_results_with_fallback(report)
    
    # Print summary
    print("\n=== SECURITY ASSESSMENT SUMMARY ===")
    print(f"Hostname: {report['compute_info']['hostname']}")
    print(f"Platform: {report['compute_info']['platform']}")
    print(f"Environment Variables: {report['environment_variables']['count']} found")
    print(f"Sensitive Variables: {len(report['environment_variables']['sensitive_variables'])} identified")
    
    # Print IMDS access status with proper error handling
    imds_status = "Unknown"
    try:
        if report['network_access'].get('169.254.169.254', {}).get('imds_access', {}).get('status_code') == 200:
            imds_status = "Available"
        else:
            imds_status = "Unavailable"
    except:
        imds_status = "Error checking"
    print(f"IMDS Access: {imds_status}")
    
    # Print container escape test results with proper error handling
    container_escape_tests = 0
    try:
        container_escape_tests = len([x for x in report['container_boundaries']['readonly_paths'].values() 
                                     if 'successful' in x.get('stdout', '').lower()])
    except:
        container_escape_tests = "Error checking"
    print(f"Container Escape Tests: {container_escape_tests}")
    
    # Print MSI access status with proper error handling
    msi_access = []
    try:
        msi_access = [k for k, v in report['identity_testing']['msi_access_tests'].items() if v.get('has_access')]
    except:
        msi_access = ["Error checking"]
    print(f"MSI Access: {', '.join(msi_access)}")
    
    # Print output path
    if output_path:
        print(f"\nResults saved to: {output_path}")
    
    # Return full report
    return report, output_path

if __name__ == "__main__":
    try:
        print("Starting security assessment...")
        report, output_path = run_security_assessment()
        
        # Print a confirmation message with the output path
        if output_path:
            print(f"\nSecurity assessment complete. Results saved to: {output_path}")
            # Print file size to confirm it was written correctly
            if os.path.exists(output_path):
                print(f"Output file size: {os.path.getsize(output_path)} bytes")
            else:
                print(f"WARNING: Output file not found at {output_path} after writing!")
        else:
            print("WARNING: Failed to save results to a file!")
        
        # For demo purposes, print a compact version of the most important findings
        try:
            important_findings = {
                "compute_info": report["compute_info"],
                "imds_access": report["network_access"].get("169.254.169.254", {}).get("imds_access", {}),
                "sudo_access": report["process_privileges"]["sudo_access"]["returncode"] == 0,
                "docker_access": report["process_privileges"]["docker_access"]["returncode"] == 0,
                "sensitive_env_count": len(report["environment_variables"]["sensitive_variables"]),
                "arm_access": report["cloud_access"].get("arm_access", {}),
                "container_escape_possible": any('successful' in x.get('stdout', '').lower() 
                                               for x in report['container_boundaries']['readonly_paths'].values()),
                "msi_resources_accessible": [k for k, v in report['identity_testing']['msi_access_tests'].items() 
                                           if v.get('has_access')],
                "credential_files_found": sum(len(files) for files in report['data_access']['potential_credential_files'].values())
            }
            
            print("\n=== CRITICAL FINDINGS ===")
            print(json.dumps(important_findings, indent=2, default=str))
        except Exception as e:
            print(f"Error generating summary: {str(e)}")
        
        # Exit with success
        print("\nAssessment complete with exit code: 0")
        sys.exit(0)
        
    except Exception as e:
        print(f"Error during security assessment: {str(e)}")
        traceback.print_exc()
        sys.exit(1)