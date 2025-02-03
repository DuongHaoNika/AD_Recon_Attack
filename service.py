import socket
import os
from dotenv import load_dotenv

load_dotenv()

def check_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def scan_dc_services(dc_ip):
    services = {
        "SMB": 445,
        "LDAP": 389,
        "LDAPS": 636,
        "RPC": 135,
        "WinRM": 5985,
        "WinRM (SSL)": 5986,
        "RDP": 3389,
        "DNS": 53,
        "Kerberos": 88,
    }
    
    results = {}
    for service, port in services.items():
        status = check_port(dc_ip, port)
        results[service] = "Open" if status else "Closed"
    
    return results

if __name__ == "__main__":
    print("Scanning...")
    scan_results = scan_dc_services(os.getenv('dc-ip'))
    
    print("Kết quả quét các dịch vụ trên Domain Controller:")
    for service, status in scan_results.items():
        print(f"{service}: {status}")