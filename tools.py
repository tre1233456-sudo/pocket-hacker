"""
Pocket Hacker - Built-in Security Tools
Encoding, hashing, network lookups, and more — right from Telegram.
"""

import base64
import hashlib
import ipaddress
import socket
import urllib.parse
import codecs
import struct
import logging
from typing import Dict, Optional

import httpx

logger = logging.getLogger(__name__)

_client = httpx.AsyncClient(timeout=15.0)


# ── Encoding / Decoding ──

def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def base64_decode(text: str) -> str:
    try:
        return base64.b64decode(text).decode()
    except Exception:
        return "❌ Invalid base64 input"

def hex_encode(text: str) -> str:
    return text.encode().hex()

def hex_decode(text: str) -> str:
    try:
        return bytes.fromhex(text.replace(" ", "")).decode()
    except Exception:
        return "❌ Invalid hex input"

def url_encode(text: str) -> str:
    return urllib.parse.quote(text)

def url_decode(text: str) -> str:
    return urllib.parse.unquote(text)

def rot13(text: str) -> str:
    return codecs.encode(text, 'rot_13')

def binary_encode(text: str) -> str:
    return ' '.join(format(b, '08b') for b in text.encode())

def binary_decode(text: str) -> str:
    try:
        bits = text.replace(" ", "")
        chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
        return ''.join(chr(int(b, 2)) for b in chars)
    except Exception:
        return "❌ Invalid binary input"

def morse_encode(text: str) -> str:
    morse = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    return ' '.join(morse.get(c.upper(), c) for c in text)

def morse_decode(text: str) -> str:
    morse_rev = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' '
    }
    return ''.join(morse_rev.get(c, '?') for c in text.split(' '))


# ── Hashing ──

def generate_hashes(text: str) -> Dict[str, str]:
    data = text.encode()
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
        "SHA512": hashlib.sha512(data).hexdigest(),
    }

def identify_hash(h: str) -> str:
    h = h.strip()
    length = len(h)
    results = []
    if length == 32 and all(c in '0123456789abcdefABCDEF' for c in h):
        results.append("MD5 / NTLM / MD4")
    if length == 40 and all(c in '0123456789abcdefABCDEF' for c in h):
        results.append("SHA1")
    if length == 56 and all(c in '0123456789abcdefABCDEF' for c in h):
        results.append("SHA224")
    if length == 64 and all(c in '0123456789abcdefABCDEF' for c in h):
        results.append("SHA256")
    if length == 128 and all(c in '0123456789abcdefABCDEF' for c in h):
        results.append("SHA512")
    if h.startswith("$2b$") or h.startswith("$2a$") or h.startswith("$2y$"):
        results.append("bcrypt")
    if h.startswith("$6$"):
        results.append("SHA-512 crypt (Linux)")
    if h.startswith("$5$"):
        results.append("SHA-256 crypt (Linux)")
    if h.startswith("$1$"):
        results.append("MD5 crypt (Linux)")
    if h.startswith("$apr1$"):
        results.append("Apache APR1-MD5")
    if ":" in h and length > 60:
        results.append("Possible salt:hash or hash:salt format")
    if not results:
        results.append(f"Unknown (length={length})")
    return ", ".join(results)


# ── Network Lookups ──

def resolve_dns(domain: str) -> Dict:
    try:
        results = {"domain": domain}
        try:
            ips = socket.getaddrinfo(domain, None)
            results["ips"] = list(set(addr[4][0] for addr in ips))
        except socket.gaierror:
            results["ips"] = ["Could not resolve"]
        return results
    except Exception as e:
        return {"error": str(e)}

async def ip_lookup(ip_or_domain: str) -> Dict:
    try:
        r = await _client.get(f"http://ip-api.com/json/{ip_or_domain}")
        if r.status_code == 200:
            return r.json()
        return {"error": f"Lookup failed ({r.status_code})"}
    except Exception as e:
        return {"error": str(e)}

async def check_headers(url: str) -> Dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = await _client.get(url, follow_redirects=True)
        security_headers = {
            "Content-Security-Policy": r.headers.get("content-security-policy", "❌ MISSING"),
            "X-Frame-Options": r.headers.get("x-frame-options", "❌ MISSING"),
            "X-Content-Type-Options": r.headers.get("x-content-type-options", "❌ MISSING"),
            "Strict-Transport-Security": r.headers.get("strict-transport-security", "❌ MISSING"),
            "X-XSS-Protection": r.headers.get("x-xss-protection", "❌ MISSING"),
            "Referrer-Policy": r.headers.get("referrer-policy", "❌ MISSING"),
            "Permissions-Policy": r.headers.get("permissions-policy", "❌ MISSING"),
        }
        server = r.headers.get("server", "Not disclosed")
        powered_by = r.headers.get("x-powered-by", "Not disclosed")
        return {
            "url": str(r.url),
            "status": r.status_code,
            "server": server,
            "powered_by": powered_by,
            "security_headers": security_headers,
            "all_headers": dict(r.headers),
        }
    except Exception as e:
        return {"error": str(e)}

async def search_cve(query: str) -> str:
    """Search for CVEs using the NIST NVD API."""
    try:
        r = await _client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": 5},
            timeout=20.0,
        )
        if r.status_code != 200:
            return f"CVE search failed ({r.status_code})"
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return "No CVEs found for that query."
        results = []
        for v in vulns[:5]:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "?")
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description")
            metrics = cve.get("metrics", {})
            score = "N/A"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore", "N/A")
                    break
            results.append(f"🔴 {cve_id} (CVSS: {score})\n{desc[:200]}")
        return "\n\n".join(results)
    except Exception as e:
        return f"CVE search error: {str(e)}"


# ── Subnet Calculator ──

def subnet_calc(cidr: str) -> Dict:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return {
            "network": str(net.network_address),
            "broadcast": str(net.broadcast_address) if hasattr(net, 'broadcast_address') else "N/A",
            "netmask": str(net.netmask),
            "hostmask": str(net.hostmask),
            "num_hosts": net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses,
            "first_host": str(list(net.hosts())[0]) if list(net.hosts()) else "N/A",
            "last_host": str(list(net.hosts())[-1]) if list(net.hosts()) else "N/A",
            "prefix": net.prefixlen,
            "is_private": net.is_private,
        }
    except Exception as e:
        return {"error": str(e)}


# ── Port Reference ──

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS/SMB",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 464: "Kerberos", 500: "IKE/IPSec", 514: "Syslog",
    587: "SMTP-TLS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

def port_info(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown service")

def get_ports_table() -> str:
    lines = []
    for port, service in sorted(COMMON_PORTS.items()):
        lines.append(f"  {port:>5}  {service}")
    return "\n".join(lines)
