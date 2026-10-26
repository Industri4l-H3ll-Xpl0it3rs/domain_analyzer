import re
import ssl
import socket
import subprocess
from urllib.parse import urlparse
import requests


def run(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return ""


def field(text, names):
    for name in names:
        match = re.search(r"^\s*" + re.escape(name) + r":\s*(.+)$", text, re.I | re.M)
        if match:
            return match.group(1).strip()
    return "No found"


url = input("Enter a URL or domain: ").strip()
site = urlparse(url if "://" in url else "https://" + url).hostname
if not site:
    print("Invalid address")
    exit()

domain = site.removeprefix("www.")
key = ("your API VirusTotal").strip()

w = run("whois", domain)
print("\nURL:", url)
print("Registration date:", field(w, ["Creation Date", "Created", "Registered On", "Registration Date", "Registration Time"]))
print("Registrar:", field(w, ["Registrar", "Registrar Name", "Sponsoring Registrar"]))
print("Registrar abuse contact:", field(w, ["Registrar Abuse Contact Email", "Abuse Email"]))


host = run("host", site)
ips = list(dict.fromkeys(re.findall(r"has address (\d+\.\d+\.\d+\.\d+)", host)))
ipv6 = list(dict.fromkeys(re.findall(r"has IPv6 address ([\da-fA-F:]+)", host)))


if not ips:
    ips = list(dict.fromkeys(re.findall(r"(?m)^\d{1,3}(?:\.\d{1,3}){3}$", run("dig", "+short", "A", site))))
if not ipv6:
    ipv6 = list(dict.fromkeys(re.findall(r"(?m)^[0-9a-fA-F:]*:[0-9a-fA-F:]+$", run("dig", "+short", "AAAA", site))))

print("IPv4:", ", ".join(ips) or "No found")
print("IPv6:", ", ".join(ipv6) or "No found")
if not ips:
    print("Failed to resolve IPv4 address. Check: dig +short A", site)
mx = run("dig", "+short", "MX", domain).strip()
print("MX-Record:", "No (Null MX)" if mx == "0 ." else mx.replace("\n", "; ") or "No found")


for ip in ips:
    info = run("whois", ip)
    company = field(info, ["OrgName", "org-name", "organisation", "owner", "NetName"])
    abuse = "No found"
    for line in info.splitlines():
        if "abuse" in line.lower():
            found = re.findall(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", line)
            if found:
                abuse = found[0]
                break
    print("\nIP:", ip)
    print("IP Operator:", company)
    print("IP Abuse Contact:", abuse)
try:
    context = ssl.create_default_context()
    with socket.create_connection((site, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=site) as connection:
            print("\nSSL: valid, expires on", connection.getpeercert().get("notAfter"))
except ssl.SSLCertVerificationError:
    print("\nSSL: certificate found, but validation failed")
except Exception:
    print("\nSSL: verification failed")

# Связанные домены: только VirusTotal Passive DNS
print("\nRelated domains from VirusTotal:")
if not key:
    print("No API key provided. You can check manually:")
    for ip in ips:
        print("https://www.virustotal.com/gui/ip-address/" + ip + "/relations")
else:
    if not ips:
        print("No IP addresses found, so the VirusTotal query was skipped")
    for ip in ips:
        print("\nIP:", ip)
        print("https://www.virustotal.com/gui/ip-address/" + ip + "/relations")
        try:
            r = requests.get(
                "https://www.virustotal.com/api/v3/ip_addresses/" + ip + "/resolutions",
                headers={"x-apikey": key}, params={"limit": 40}, timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                print("Total in VirusTotal:", data.get("meta", {}).get("count", "?"))
                names = {x.get("attributes", {}).get("host_name") for x in data.get("data", [])}
                for name in sorted(x for x in names if x):
                    print("-", name)
            else:
                print("Error VirusTotal:", r.status_code)
                if r.status_code == 401:
                    print("Check API-key")
                elif r.status_code == 403:
                    print("This request is not available on your current plan")
                elif r.status_code == 429:
                    print("API rate limit exceeded. Please try again later")
        except requests.RequestException:
            print("Failed to connect to VirusTotal")

