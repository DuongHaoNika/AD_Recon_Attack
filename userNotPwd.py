# import os
# from ldap3 import Server, Connection, ALL, SUBTREE
# from dotenv import load_dotenv

# # Load biến môi trường từ file .env
# load_dotenv()

# def find_users_no_password_required():
#     try:
#         # Lấy thông tin kết nối từ biến môi trường
#         ad_server = f"ldap://{os.getenv('dc-ip')}"
#         user_dn = f"{os.getenv('username_AD')}"
#         password = os.getenv('password_AD')
#         base_dn = f"DC={os.getenv('DC1')},DC={os.getenv('DC2')}"
        
#         # Kết nối tới AD
#         server = Server(ad_server, get_info=ALL)
#         conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        
#         # Tìm kiếm người dùng có flag 'Password Not Required'
#         search_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))'
#         conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=['sAMAccountName', 'distinguishedName'])
        
#         # Hiển thị kết quả
#         for entry in conn.entries:
#             print(f"User: {entry.sAMAccountName}, DN: {entry.distinguishedName}")
        
#         conn.unbind()
#     except Exception as e:
#         print(f"Lỗi: {e}")

# find_users_no_password_required()

from ldap3 import Server, Connection, SUBTREE, ALL
import json
from dotenv import load_dotenv
import os
import sys

def check_env_file():
    """Kiểm tra file .env và các biến môi trường cần thiết"""
    required_vars = ['DC1', 'DC2', 'domain', 'username_AD', 'password_AD', 'dc-ip']
    
    if not os.path.exists('.env'):
        print("Lỗi: Không tìm thấy file .env")
        return False
    
    load_dotenv()
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Lỗi: Thiếu các biến môi trường sau trong file .env: {', '.join(missing_vars)}")
        return False
    
    return True

def check_no_password_accounts():
    """
    Kiểm tra các tài khoản AD không yêu cầu mật khẩu
    """
    if not check_env_file():
        return None

    try:
        # Lấy thông tin cấu hình
        DC1 = os.getenv('DC1')
        DC2 = os.getenv('DC2')
        domain = os.getenv('domain')
        username_AD = os.getenv('username_AD')
        password_AD = os.getenv('password_AD')
        dc_ip = os.getenv('dc-ip')

        # Thiết lập kết nối
        server_address = f"ldap://{dc_ip}"
        domain_dn = f"DC={DC1},DC={DC2}"
        
        # Kết nối tới AD server
        server = Server(server_address, get_info=ALL)
        conn = Connection(
            server,
            user=username_AD,
            password=password_AD,
            auto_bind=True
        )
        
        # LDAP filter và thuộc tính
        search_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))'
        attributes = [
            'sAMAccountName',
            'distinguishedName',
            'userAccountControl',
            'description'
        ]
        
        # Thực hiện tìm kiếm
        if not conn.search(
            search_base=domain_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes
        ):
            print(f"Lỗi tìm kiếm LDAP: {conn.last_error}")
            return None
        
        # Xử lý kết quả
        results = []
        for entry in conn.entries:
            user_info = {
                'username': entry.sAMAccountName.value,
                'dn': entry.distinguishedName.value,
                'account_control': entry.userAccountControl.value,
                'description': entry.description.value if hasattr(entry, 'description') else ''
            }
            results.append(user_info)
        
        # Tạo báo cáo
        report = {
            'domain': domain,
            'dc_server': dc_ip,
            'total_accounts_found': len(results),
            'accounts': results
        }
        
        # Lưu kết quả
        filename = 'ad_no_password_accounts.json'
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
            
        print(f"\nTìm thấy {len(results)} tài khoản không yêu cầu mật khẩu")
        print(f"Kết quả chi tiết đã được lưu vào file: {filename}")
        
        return results
        
    except Exception as e:
        print(f"Lỗi: {str(e)}")
        return None
    finally:
        if 'conn' in locals() and conn:
            conn.unbind()

if __name__ == "__main__":
    try:
        check_no_password_accounts()
    except KeyboardInterrupt:
        print("\nĐã hủy quá trình kiểm tra.")
        sys.exit(1)