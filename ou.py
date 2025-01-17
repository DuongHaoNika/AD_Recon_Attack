from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
import socket
import re
from typing import List, Dict
import os
from dotenv import load_dotenv

load_dotenv()

def get_ou_gpo_mapping():
    """
    Liệt kê tất cả OUs và các GPO được liên kết với chúng
    """
    try:
        # Kết nối tới AD
        domain = socket.getfqdn().split('.', 1)[1]
        base_dn = ','.join(f'DC={dc}' for dc in domain.split('.'))
        
        server = Server(domain, get_info=ALL)
        server_address = os.getenv('dc-ip')  # Địa chỉ domain controller, ví dụ: "dc1.example.com"
        username = os.getenv('username_AD')  # Tên người dùng, ví dụ: "administrator@example.com"
        password = os.getenv('password_AD')
        conn = Connection(server, user=username, password=password, auto_bind=True)
        
        if not conn.bind():
            print("Failed to connect to Active Directory")
            return

        def get_gpo_name(gpo_dn: str) -> str:
            """Lấy tên của GPO từ GUID"""
            try:
                # Tìm trong container GPOs
                gpo_cn = gpo_dn.split(',')[0].replace('CN=', '')
                search_base = f"CN=Policies,CN=System,{base_dn}"
                
                conn.search(search_base,
                          f'(distinguishedName={gpo_dn})',
                          attributes=['displayName'])
                
                if conn.entries and hasattr(conn.entries[0], 'displayName'):
                    return conn.entries[0].displayName.value
                return gpo_cn
            except:
                return gpo_dn

        # Tìm tất cả OUs
        print("\nScanning for OUs and their linked GPOs...")
        print("=" * 50)
        
        conn.search(base_dn,
                   '(objectClass=organizationalUnit)',
                   attributes=['distinguishedName', 'name', 'gPLink', 'description'])
        
        ous = []
        for ou in conn.entries:
            ou_info = {
                'name': ou.name.value,
                'dn': ou.entry_dn,
                'gpos': [],
                'description': ou.description.value if hasattr(ou, 'description') else None
            }
            
            # Phân tích GPLink để lấy danh sách GPOs
            if hasattr(ou, 'gPLink') and ou.gPLink.value:
                # GPLink format: [LDAP://cn={GPO-GUID},cn=policies,cn=system,DC=domain,DC=com;0]
                gpo_links = re.findall(r'LDAP://([^;]+);(\d+)', ou.gPLink.value)
                
                for gpo_dn, options in gpo_links:
                    # options: 0 = enabled, 1 = disabled, 2 = enforced
                    enabled = not (int(options) & 1)
                    enforced = int(options) & 2
                    
                    gpo_name = get_gpo_name(gpo_dn)
                    
                    ou_info['gpos'].append({
                        'name': gpo_name,
                        'dn': gpo_dn,
                        'enabled': enabled,
                        'enforced': enforced
                    })
            
            ous.append(ou_info)
        
        # Sắp xếp OUs theo tên
        ous.sort(key=lambda x: x['name'])
        
        # In kết quả
        print("\nOrganizational Units and their Group Policies:")
        print("-" * 50)
        
        for ou in ous:
            print(f"\nOU: {ou['name']}")
            if ou['description']:
                print(f"Description: {ou['description']}")
            print(f"DN: {ou['dn']}")
            
            if ou['gpos']:
                print("Linked GPOs:")
                for i, gpo in enumerate(ou['gpos'], 1):
                    status = []
                    if not gpo['enabled']:
                        status.append('Disabled')
                    if gpo['enforced']:
                        status.append('Enforced')
                    
                    status_str = f" ({', '.join(status)})" if status else ""
                    print(f"  {i}. {gpo['name']}{status_str}")
            else:
                print("No GPOs linked to this OU")
                
        conn.unbind()
        
    except Exception as e:
        print(f"Error: {str(e)}")