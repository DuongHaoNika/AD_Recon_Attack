from ldap3 import Server, Connection, ALL, SUBTREE
from dotenv import load_dotenv
import os
from datetime import datetime
import json

load_dotenv()

def list_domain_computers(server_address, username, password, search_base, computer_name=None):
    try:
        # Kết nối tới máy chủ LDAP
        server = Server(server_address, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        
        # Tạo filter tìm kiếm
        if computer_name:
            search_filter = f'(&(objectClass=computer)(cn={computer_name}))'
        else:
            search_filter = '(objectClass=computer)'
            
        # Thực hiện truy vấn
        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                'cn',                    # Computer name
                'dNSHostName',           # DNS host name
                'operatingSystem',       # OS
                'operatingSystemVersion', # OS version
                'lastLogon',             # Last logon time
                'whenCreated',           # Creation time
                'whenChanged',           # Last modified time
                'userAccountControl',    # Account status
                'distinguishedName',     # DN
                'location',              # Location
                'description'            # Description
            ]
        )

        computers = []
        for entry in conn.entries:
            # Chuyển đổi lastLogon timestamp sang datetime
            last_logon = None
            if hasattr(entry, 'lastLogon') and entry.lastLogon.value:
                try:
                    # Windows FileTime to datetime
                    timestamp = int(entry.lastLogon.value) / 10000000 - 11644473600
                    last_logon = datetime.fromtimestamp(timestamp)
                except:
                    last_logon = None

            computer_info = {
                'name': entry.cn.value if hasattr(entry, 'cn') else None,
                'dns_hostname': entry.dNSHostName.value if hasattr(entry, 'dNSHostName') else None,
                'operating_system': entry.operatingSystem.value if hasattr(entry, 'operatingSystem') else None,
                'os_version': entry.operatingSystemVersion.value if hasattr(entry, 'operatingSystemVersion') else None,
                'last_logon': last_logon,
                'created': entry.whenCreated.value if hasattr(entry, 'whenCreated') else None,
                'modified': entry.whenChanged.value if hasattr(entry, 'whenChanged') else None,
                'distinguished_name': entry.distinguishedName.value if hasattr(entry, 'distinguishedName') else None,
                'location': entry.location.value if hasattr(entry, 'location') else None,
                'description': entry.description.value if hasattr(entry, 'description') else None,
                'status': get_account_status(entry.userAccountControl.value) if hasattr(entry, 'userAccountControl') else None
            }
            computers.append(computer_info)

        return computers

    except Exception as e:
        print(f"Error: {e}")
        return None

def get_account_status(uac):
    """Phân tích trạng thái tài khoản từ userAccountControl"""
    status = []
    
    if uac & 0x0002:  # ADS_UF_ACCOUNTDISABLE
        status.append("Disabled")
    else:
        status.append("Enabled")
        
    if uac & 0x0020:  # PASSWD_NOTREQD
        status.append("No Password Required")
        
    if uac & 0x0040:  # PASSWD_CANT_CHANGE
        status.append("Password Can't Change")
        
    if uac & 0x0080:  # ENCRYPTED_TEXT_PWD_ALLOWED
        status.append("Encrypted Text Password Allowed")
        
    if uac & 0x0100:  # TEMP_DUPLICATE_ACCOUNT
        status.append("Temporary Duplicate Account")
        
    if uac & 0x1000:  # WORKSTATION_TRUST_ACCOUNT
        status.append("Workstation Trust Account")
        
    if uac & 0x2000:  # SERVER_TRUST_ACCOUNT
        status.append("Server Trust Account")
        
    return status

def format_output(computers, output_format='json'):
    """Định dạng đầu ra theo yêu cầu"""
    if output_format.lower() == 'json':
        return json.dumps(computers, indent=2, default=str)
    
    elif output_format.lower() == 'text':
        output = []
        for computer in computers:
            output.append(f"Computer Name: {computer['name']}")
            output.append(f"DNS Hostname: {computer['dns_hostname']}")
            output.append(f"Operating System: {computer['operating_system']} {computer['os_version']}")
            output.append(f"Last Logon: {computer['last_logon']}")
            output.append(f"Status: {', '.join(computer['status']) if computer['status'] else 'Unknown'}")
            output.append(f"Location: {computer['location']}")
            output.append(f"Description: {computer['description']}")
            output.append("-" * 50)
        return "\n".join(output)
    
    return "Unsupported format"

if __name__ == "__main__":
    # Lấy thông tin từ biến môi trường
    domain = os.getenv('domain')
    server_address = 'ldap://' + domain
    username = os.getenv('username_AD')
    password = os.getenv('password_AD')
    search_base = f"DC={os.getenv('DC1')},DC={os.getenv('DC2')}"
    
    # Có thể truyền tên máy tính cụ thể hoặc để None để lấy tất cả
    computer_name = None  # Ví dụ: "DESKTOP-ABC123"
    
    # Lấy danh sách máy tính
    computers = list_domain_computers(server_address, username, password, search_base, computer_name)
    
    if computers:
        # In kết quả theo định dạng mong muốn (json hoặc text)
        print(format_output(computers, output_format='text'))