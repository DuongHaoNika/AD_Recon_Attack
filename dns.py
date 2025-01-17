from ldap3 import Server, Connection, ALL, SUBTREE
from datetime import datetime
from dotenv import load_dotenv
import os
import struct
import socket

load_dotenv()

class DNSQuery:
    def __init__(self, server_address, username, password, domain):
        self.server = Server(server_address, get_info=ALL)
        self.conn = Connection(self.server, user=username, password=password, auto_bind=True)
        self.domain = domain

    def get_dns_records(self, zone_name):
        """Lấy tất cả các bản ghi DNS từ một zone cụ thể."""
        try:
            # Định nghĩa DN của zone DNS
            dns_zone_dn = f"DC={zone_name},CN=MicrosoftDNS,DC=DomainDnsZones,DC={self.domain.split('.')[0]},DC={self.domain.split('.')[1]}"
            
            # Tìm kiếm tất cả các bản ghi trong zone
            self.conn.search(
                search_base=dns_zone_dn,
                search_filter="(objectClass=dnsNode)",
                search_scope=SUBTREE,
                attributes=["dc", "dnsRecord", "whenCreated", "whenChanged"]
            )
            
            records = []
            for entry in self.conn.entries:
                record_info = {
                    "name": entry.dc.value if hasattr(entry, "dc") else None,
                    "created": entry.whenCreated.value if hasattr(entry, "whenCreated") else None,
                    "modified": entry.whenChanged.value if hasattr(entry, "whenChanged") else None,
                    "records": self.parse_dns_record(entry.dnsRecord.raw_values) if hasattr(entry, "dnsRecord") else None
                }
                records.append(record_info)
            return records

        except Exception as e:
            print(f"Lỗi khi lấy bản ghi DNS từ zone {zone_name}: {e}")
            return None

    def parse_dns_record(self, dns_records):
        """Phân tích dữ liệu bản ghi DNS."""
        if not dns_records:
            return None

        record_types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
        }

        records = []
        for raw_record in dns_records:
            try:
                # Loại bản ghi
                record_type = raw_record[2] if len(raw_record) > 2 else None
                record_info = {
                    "type": record_types.get(record_type, f"Unknown ({record_type})"),
                }

                # TTL (Thời gian tồn tại)
                if len(raw_record) >= 8:
                    ttl = struct.unpack("!I", raw_record[4:8])[0]
                    record_info["ttl"] = ttl

                # Dữ liệu tùy theo loại bản ghi
                if record_type == 1:  # A Record
                    ip_bytes = raw_record[-4:]
                    record_info["ip_address"] = socket.inet_ntoa(ip_bytes)

                elif record_type == 28:  # AAAA Record
                    ip_bytes = raw_record[-16:]
                    record_info["ip_address"] = socket.inet_ntop(socket.AF_INET6, ip_bytes)

                elif record_type in [2, 5]:  # NS hoặc CNAME
                    hostname = self.extract_hostname(raw_record[12:])
                    record_info["target"] = hostname

                records.append(record_info)

            except Exception as e:
                print(f"Lỗi khi phân tích bản ghi DNS: {e}")
                records.append({"type": "Unknown", "error": str(e)})

        return records

    def extract_hostname(self, data):
        """Giải mã hostname từ dữ liệu DNS."""
        try:
            hostname = []
            i = 0
            while i < len(data):
                length = data[i]
                if length == 0:
                    break
                hostname.append(data[i + 1:i + 1 + length].decode("utf-8"))
                i += length + 1
            return ".".join(hostname)
        except Exception as e:
            print(f"Lỗi khi giải mã hostname: {e}")
            return None


def main():
    # Thông tin kết nối
    domain = os.getenv('domain')
    server_address = 'ldap://' + domain
    username = os.getenv('username_AD')
    password = os.getenv('password_AD')

    # Khởi tạo đối tượng DNSQuery
    dns_query = DNSQuery(server_address, username, password, domain)
    
    # Tên zone DNS cần truy vấn
    dns_zone = "duongquanghao110.it"  # Thay bằng tên zone bạn muốn liệt kê
    
    # Lấy bản ghi DNS từ zone
    print(f"Liệt kê bản ghi DNS trong zone: {dns_zone}")
    dns_records = dns_query.get_dns_records(dns_zone)
    
    # In danh sách các bản ghi
    if dns_records:
        for record in dns_records:
            print("\n------------------------------------")
            print(f"Name: {record['name']}")
            print(f"Created: {record['created']}")
            print(f"Modified: {record['modified']}")
            print("Records:")
            if record["records"]:
                for rec in record["records"]:
                    print(f"  Type: {rec['type']}")
                    if "ip_address" in rec:
                        print(f"    IP Address: {rec['ip_address']}")
                    if "target" in rec:
                        print(f"    Target: {rec['target']}")
                    if "ttl" in rec:
                        print(f"    TTL: {rec['ttl']}")
            else:
                print("  No records found.")
            print("------------------------------------")
    else:
        print(f"Không tìm thấy bản ghi DNS trong zone {dns_zone}.")

if __name__ == "__main__":
    main()
