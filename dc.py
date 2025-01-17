from ldap3 import Server, Connection, ALL, SUBTREE
from dotenv import load_dotenv
import os

load_dotenv()

def get_domain_controllers(domain_name):
    try:
        domain = os.getenv('domain')
        server_address = 'ldap://' + domain
        username = os.getenv('username_AD')
        password = os.getenv('password_AD')
        # Xác định server LDAP (thường là DC đầu tiên của domain)
        server = Server(server_address, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)

        # Kết nối với server LDAP
        if not conn.bind():
            print(f"Không thể kết nối với domain controller {domain_name}")
            return []

        search_base = 'OU=Domain Controllers,DC=duongquanghao110,DC=it'  # Thay đổi theo cấu trúc DN của bạn
        search_filter = '(objectClass=computer)'

        # Truy vấn tất cả các domain controllers
        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=['dNSHostName'],
            search_scope=SUBTREE
        )

        dc_list = []
        for entry in conn.entries:
            if 'dNSHostName' in entry.entry_attributes:
                dc_list.append(entry.dNSHostName.value)

        return dc_list

    except Exception as e:
        print(f"Error: {e}")
        return []

# Thay 'duongquanghao110.it' bằng tên domain của bạn
domain_name = os.getenv('domain')
domain_controllers = get_domain_controllers(domain_name)

print(f"Domain controllers in domain '{domain_name}':")
for dc in domain_controllers:
    print(dc)
