from ldap3 import Server, Connection, ALL
from dotenv import load_dotenv
import os

load_dotenv()

username = os.getenv('username')
password = os.getenv('password')

def list_all_users(server_address, username, password, search_base):
    try:
        # Kết nối tới máy chủ LDAP
        server = Server(server_address, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        # Thực hiện truy vấn để tìm tất cả user
        conn.search(
            search_base=search_base,
            search_filter='(objectClass=user)',  # Lọc chỉ đối tượng user
            attributes=['cn', 'sAMAccountName', 'mail']  # Các thuộc tính cần lấy
        )

        # Hiển thị danh sách người dùng
        print(f"Found {len(conn.entries)} users:")
        for entry in conn.entries:
            print(entry)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Thay đổi các thông tin dưới đây theo domain của bạn
    domain = os.getenv('domain')
    server_address = 'ldap://' + domain 
    username = os.getenv('username_AD')     
    password = os.getenv('password_AD')                   
    search_base = f"DC={os.getenv('DC1')},DC={os.getenv('DC2')}"         

    list_all_users(server_address, username, password, search_base)
