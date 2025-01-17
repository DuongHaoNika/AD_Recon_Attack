from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
import os
from dotenv import load_dotenv

load_dotenv()

def get_group_members(group_name):
    """
    Liệt kê tất cả users trong một group, bao gồm cả nested groups
    
    Args:
        group_name (str): Tên của group cần tìm
    """
    try:
        # Tự động tìm domain controller
        import socket
        domain = socket.getfqdn().split('.', 1)[1]
        server = Server(domain, get_info=ALL)
        
        server_address = os.getenv('dc-ip')  # Địa chỉ domain controller, ví dụ: "dc1.example.com"
        username = os.getenv('username_AD')  # Tên người dùng, ví dụ: "administrator@example.com"
        password = os.getenv('password_AD')
        conn = Connection(server, user=username, password=password, auto_bind=True)
        
        if not conn.bind():
            print("Failed to connect to Active Directory")
            return
        
        # Tìm DN của group
        base_dn = ','.join(['DC=' + dc for dc in domain.split('.')])
        conn.search(
            base_dn,
            f'(&(objectClass=group)(sAMAccountName={group_name}))',
            attributes=['distinguishedName', 'member', 'description']
        )
        
        if not conn.entries:
            print(f"Group '{group_name}' not found")
            return
            
        group_dn = conn.entries[0].distinguishedName
        print(f"\nGroup: {group_name}")
        if hasattr(conn.entries[0], 'description') and conn.entries[0].description:
            print(f"Description: {conn.entries[0].description}")
        
        def get_nested_members(member_dn, processed_groups=None):
            if processed_groups is None:
                processed_groups = set()
                
            # Kiểm tra xem đối tượng là user hay group
            conn.search(
                member_dn,
                '(objectClass=*)',
                attributes=['objectClass', 'sAMAccountName', 'mail', 
                          'displayName', 'userAccountControl', 'member']
            )
            
            if not conn.entries:
                return []
                
            entry = conn.entries[0]
            members = []
            
            # Nếu là group, xử lý đệ quy
            if 'group' in [oc.lower() for oc in entry.objectClass]:
                if member_dn not in processed_groups:
                    processed_groups.add(member_dn)
                    if hasattr(entry, 'member'):
                        for nested_member in entry.member:
                            members.extend(get_nested_members(nested_member, processed_groups))
            # Nếu là user
            elif 'user' in [oc.lower() for oc in entry.objectClass]:
                user_info = {
                    'username': entry.sAMAccountName.value,
                    'display_name': getattr(entry, 'displayName', {}).value,
                    'email': getattr(entry, 'mail', {}).value,
                    'enabled': not (getattr(entry, 'userAccountControl', {}).value & 2)
                }
                members.append(user_info)
                
            return members
            
        # Lấy danh sách thành viên
        all_members = []
        if hasattr(conn.entries[0], 'member'):
            for member_dn in conn.entries[0].member:
                all_members.extend(get_nested_members(member_dn))
        
        # Hiển thị kết quả
        print(f"\nTotal members found: {len(all_members)}")
        print("\nMembers:")
        for i, member in enumerate(all_members, 1):
            print(f"\n{i}. Username: {member['username']}")
            if member['display_name']:
                print(f"   Display Name: {member['display_name']}")
            if member['email']:
                print(f"   Email: {member['email']}")
            print(f"   Account Status: {'Enabled' if member['enabled'] else 'Disabled'}")
            
        conn.unbind()
        
    except Exception as e:
        print(f"Error: {str(e)}")
