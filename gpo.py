import win32com.client
import re
import os
from dotenv import load_dotenv

load_dotenv()

def get_all_gpos():
    # Tạo kết nối với Group Policy
    gpo = win32com.client.Dispatch('GPMGMT.GPM')
    domain = gpo.GetDomain(os.getenv('domain'))  # Thay đổi 'your_domain.com' thành tên domain của bạn
    gpos = domain.GetGPOs()  # Lấy danh sách tất cả các GPO
    print(gpos)

    return gpos

def check_gpo_for_security_issues(gpo):
    # Kiểm tra Clear Text Password Storage (ClearTextPassword = 1)
    if 'ClearTextPassword' in gpo:
        if gpo['ClearTextPassword'] == 1:
            print(f"GPO {gpo.Name} contains Clear Text Password Storage risk.")

    # Kiểm tra GPP Passwords (MS14-025)
    if 'GPP' in gpo and 'Passwords' in gpo:
        if gpo['Passwords'] == 'Encrypted':
            print(f"GPO {gpo.Name} contains potential GPP Passwords vulnerability.")

    # Kiểm tra NetNTLMv1 Authentication Enabled (LmCompatibilityLevel settings)
    if 'LmCompatibilityLevel' in gpo:
        if gpo['LmCompatibilityLevel'] == 1:
            print(f"GPO {gpo.Name} has NetNTLMv1 Authentication Enabled.")

if __name__ == "__main__":
    gpos = get_all_gpos()
    for gpo in gpos:
        check_gpo_for_security_issues(gpo)
