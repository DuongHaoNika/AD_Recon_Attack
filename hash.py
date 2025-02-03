import os
from dotenv import load_dotenv, set_key
from Crypto.Hash import MD4

load_dotenv()


def plaintext_to_ntlm(password):
    # Chuyển đổi mật khẩu sang Unicode (UTF-16 LE)
    password_utf16 = password.encode('utf-16le')
    hash = MD4.new(password_utf16)
    return hash.hexdigest().lower()

if __name__ == "__main__":
    if not os.getenv("NTLM"):
        password = os.getenv("password_AD")
        ntlm_hash = plaintext_to_ntlm(password)
        set_key(".env","ntlm", ntlm_hash)