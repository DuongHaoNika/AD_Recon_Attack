# from ldap3 import Server, Connection, ALL
# from dotenv import load_dotenv
# import os

# load_dotenv()

# # Lấy thông tin từ biến môi trường
# username = os.getenv('username')
# password = os.getenv('password')

# def list_all_groups(server_address, username, password, search_base):
#     try:
#         # Kết nối tới máy chủ LDAP
#         server = Server(server_address, get_info=ALL)
#         conn = Connection(server, user=username, password=password, auto_bind=True)
        
#         # Thực hiện truy vấn để tìm tất cả các group
#         conn.search(
#             search_base=search_base,
#             search_filter='(objectClass=group)',  # Lọc chỉ đối tượng group
#             attributes=['cn', 'sAMAccountName']  # Các thuộc tính cần lấy
#         )

#         # Hiển thị danh sách group
#         print(f"Found {len(conn.entries)} groups:")
#         for entry in conn.entries:
#             print(entry)

#     except Exception as e:
#         print(f"Error: {e}")

# if __name__ == "__main__":
#     # Thay đổi các thông tin dưới đây theo domain của bạn
#     domain = os.getenv('domain')
#     server_address = 'ldap://' + domain 
#     username = os.getenv('username_AD')     
#     password = os.getenv('password_AD')                   
#     search_base = f"DC={os.getenv('DC1')},DC={os.getenv('DC2')}"

#     list_all_groups(server_address, username, password, search_base)


from ldap3 import Server, Connection, ALL, SUBTREE
from dotenv import load_dotenv
import os
import json
from datetime import datetime

load_dotenv()

def get_group_permissions(server_address, username, password, search_base, group_name=None):
    try:
        # Kết nối tới máy chủ LDAP
        server = Server(server_address, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        
        # Tạo filter tìm kiếm
        if group_name:
            search_filter = f'(&(objectClass=group)(cn={group_name}))'
        else:
            search_filter = '(objectClass=group)'
            
        # Thực hiện truy vấn với các thuộc tính bảo mật
        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                'cn',                          # Group name
                'sAMAccountName',              # Account name
                'member',                      # Group members
                'objectSid',                   # Security identifier
                'adminCount',                  # Admin privilege indicator
                'groupType',                   # Group type/scope
                'nTSecurityDescriptor',        # Security descriptor
                'whenCreated',                 # Creation time
                'whenChanged'                  # Last modified time
            ]
        )

        results = []
        for entry in conn.entries:
            group_info = {
                'name': entry.cn.value if hasattr(entry, 'cn') else None,
                'sam_account_name': entry.sAMAccountName.value if hasattr(entry, 'sAMAccountName') else None,
                'member_count': len(entry.member) if hasattr(entry, 'member') else 0,
                'admin_count': entry.adminCount.value if hasattr(entry, 'adminCount') else None,
                'group_type': analyze_group_type(entry.groupType.value) if hasattr(entry, 'groupType') else None,
                'created': entry.whenCreated.value if hasattr(entry, 'whenCreated') else None,
                'modified': entry.whenChanged.value if hasattr(entry, 'whenChanged') else None
            }

            # Phân tích chi tiết về loại group
            if hasattr(entry, 'groupType'):
                group_info['group_details'] = get_group_type_details(entry.groupType.value)

            results.append(group_info)

        return results

    except Exception as e:
        print(f"Error: {e}")
        return None

def analyze_group_type(group_type):
    """Phân tích loại group dựa trên giá trị groupType"""
    group_types = {
        2: "Global Distribution Group",
        4: "Domain Local Distribution Group",
        8: "Universal Distribution Group",
        -2147483646: "Global Security Group",
        -2147483644: "Domain Local Security Group",
        -2147483640: "Universal Security Group"
    }
    return group_types.get(group_type, "Unknown Group Type")

def get_group_type_details(group_type):
    """Phân tích chi tiết các thuộc tính của group"""
    details = []
    
    # Security vs Distribution
    if group_type & 0x80000000:
        details.append("Security Group")
    else:
        details.append("Distribution Group")
    
    # Scope
    if group_type & 0x00000002:
        details.append("Global Scope")
    elif group_type & 0x00000004:
        details.append("Domain Local Scope")
    elif group_type & 0x00000008:
        details.append("Universal Scope")
        
    return details

if __name__ == "__main__":
    domain = os.getenv('domain')
    server_address = 'ldap://' + domain
    username = os.getenv('username_AD')
    password = os.getenv('password_AD')
    search_base = f"DC={os.getenv('DC1')},DC={os.getenv('DC2')}"
    
    # Có thể truyền tên group cụ thể hoặc để None để lấy tất cả
    group_name = None  # Ví dụ: "Domain Admins"
    
    results = get_group_permissions(server_address, username, password, search_base, group_name)
    
    if results:
        print(json.dumps(results, indent=2, default=str))