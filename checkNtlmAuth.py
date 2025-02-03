import sys
from impacket.smbconnection import SMBConnection
from dotenv import load_dotenv
import os

load_dotenv()

def check_ntlm_support(dc_ip, username, ntlm_hash):
    try:
        lmhash, nthash = ntlm_hash.split(':')
        conn = SMBConnection(dc_ip, dc_ip)
        conn.login(user=username, password='', domain='', lmhash=lmhash, nthash=nthash)
        
        print(f"[+] Domain Controller {dc_ip} hỗ trợ xác thực bằng NTLM hash!")
        conn.logoff()
    except Exception as e:
        print(f"[-] Domain Controller {dc_ip} không hỗ trợ xác thực NTLM hash hoặc gặp lỗi: {e}")

if __name__ == "__main__":
    dc_ip = os.getenv('dc-ip')
    username = os.getenv('username2')
    ntlm_hash = ":" + os.getenv('ntlm')
    check_ntlm_support(dc_ip, username, ntlm_hash)
