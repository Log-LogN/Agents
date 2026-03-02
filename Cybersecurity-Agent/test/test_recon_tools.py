import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mcp_tools.recon.tools.dns_lookup import dns_lookup
from mcp_tools.recon.tools.port_scan import port_scan
from mcp_tools.recon.tools.whois_lookup import whois_lookup

tests = [
    ("DNS", dns_lookup, "google.com"),
    ("Port Scan", port_scan, "google.com"),
    ("WHOIS", whois_lookup, "google.com"),
]

for name, func, value in tests:
    print("\n" + "="*60)
    print(name, value)
    result = func(value)
    print(result)