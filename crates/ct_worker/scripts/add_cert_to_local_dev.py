import base64
from datetime import datetime
import json
import urllib.request
import socket
import ssl
import sys

HOST = "www.google.com"

# Need >=3.13 to use conn.get_unverified_chain()
if sys.version_info < (3, 13, 0):
    cur_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print("Error: This script requires Python 3.13 or newer. ")
    print(f"Current version is {cur_version}")
    exit(1)

# Make a connection to HOST
context = ssl.create_default_context()
conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=HOST)
conn.connect((HOST, 443))

# Get the leaf cert. That's the not_after we use to decide which shard to submit to
parsed_cert = conn.getpeercert()
# Get the cert chain. This is what we'll submit
der_cert_chain = conn.get_unverified_chain()
b64_cert_chain = [str(base64.b64encode(c), encoding="utf-8") for c in der_cert_chain]

# Figure out the year and half-year that this not_after belongs to. Eg dev2026h2a is the second half
# of 2026
not_after = datetime.strptime(parsed_cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
not_after_year = not_after.year
not_after_half = 1 if not_after.month < 7 else 2
log_name = f"dev{not_after_year}h{not_after_half}a"

# Make a POST request to localhost add-chain
payload = {"chain": b64_cert_chain}
request = urllib.request.Request(
    f"http://localhost:8787/logs/{log_name}/ct/v1/add-chain",
    data=bytes(json.dumps(payload), encoding="utf-8"),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
try:
    urllib.request.urlopen(request, timeout=5)
except Exception as e:
    print("Error: ", e)
    sys.exit(1)

print("Success")
