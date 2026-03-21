"""
Pocket Hacker - Built-in Security Tools
Encoding, hashing, network lookups, OSINT, web scanning, breach checks, and more.
"""

import base64
import hashlib
import ipaddress
import socket
import urllib.parse
import codecs
import struct
import re
import json
import logging
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

_client = httpx.AsyncClient(
    timeout=20.0,
    follow_redirects=True,
    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
)


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


# ══════════════════════════════════════════════
# ══  OSINT — Real lookups, not just AI chat  ══
# ══════════════════════════════════════════════

async def phone_lookup(phone: str) -> Dict:
    """OSINT phone number lookup via free APIs."""
    results = {"phone": phone}

    # NumVerify (free, no key needed for basic)
    try:
        clean = re.sub(r'[^\d+]', '', phone)
        r = await _client.get(f"https://phonevalidation.abstractapi.com/v1/?phone={clean}")
        if r.status_code == 200:
            data = r.json()
            results.update({k: v for k, v in data.items() if v})
    except Exception:
        pass

    # Try Google phonebook style
    try:
        r = await _client.get(
            f"https://api.apilayer.com/number_verification/validate?number={phone}",
            headers={"apikey": "free_tier"},
            timeout=10
        )
        if r.status_code == 200:
            results["validation"] = r.json()
    except Exception:
        pass

    return results


async def email_osint(email: str) -> Dict:
    """OSINT email lookup — breaches, validation, social accounts."""
    results = {"email": email}

    # Check Have I Been Pwned (public breach list page)
    try:
        r = await _client.get(
            f"https://haveibeenpwned.com/unifiedsearch/{email}",
            headers={
                "User-Agent": "PocketHacker-OSINT",
            },
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            breaches = data.get("Breaches", [])
            results["breaches_found"] = len(breaches)
            results["breached_sites"] = [
                {
                    "name": b.get("Name"),
                    "date": b.get("BreachDate"),
                    "data_exposed": b.get("DataClasses", []),
                    "records": b.get("PwnCount"),
                }
                for b in breaches[:10]
            ]
            pastes = data.get("Pastes", [])
            results["pastes_found"] = len(pastes)
        elif r.status_code == 404:
            results["breaches_found"] = 0
            results["status"] = "No breaches found"
        else:
            results["hibp_status"] = r.status_code
    except Exception as e:
        results["hibp_error"] = str(e)

    # Email validation
    try:
        domain = email.split("@")[-1] if "@" in email else ""
        if domain:
            mx_records = []
            try:
                answers = socket.getaddrinfo(domain, 25)
                mx_records = list(set(a[4][0] for a in answers))
            except Exception:
                pass
            results["domain"] = domain
            results["mx_ips"] = mx_records
            results["domain_valid"] = len(mx_records) > 0
    except Exception:
        pass

    return results


async def username_search(username: str) -> Dict:
    """Search for a username across platforms."""
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter/X": f"https://x.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Medium": f"https://medium.com/@{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "HackerOne": f"https://hackerone.com/{username}",
        "BugCrowd": f"https://bugcrowd.com/{username}",
        "Dev.to": f"https://dev.to/{username}",
        "Replit": f"https://replit.com/@{username}",
        "Cash App": f"https://cash.app/${username}",
    }
    found = {}
    not_found = []

    async def check(name, url):
        try:
            r = await _client.get(url, timeout=8, follow_redirects=False)
            if r.status_code in (200, 301, 302):
                return name, url, True
            return name, url, False
        except Exception:
            return name, url, False

    import asyncio
    tasks = [check(name, url) for name, url in platforms.items()]
    results = await asyncio.gather(*tasks)

    for name, url, exists in results:
        if exists:
            found[name] = url
        else:
            not_found.append(name)

    return {"username": username, "found": found, "not_found": not_found}


async def domain_recon(domain: str) -> Dict:
    """Full domain recon — DNS, WHOIS-style, tech stack, subdomains."""
    results = {"domain": domain}

    # DNS records
    try:
        ips = socket.getaddrinfo(domain, None)
        results["ips"] = list(set(addr[4][0] for addr in ips))
    except Exception:
        results["ips"] = []

    # HTTP fingerprint
    for scheme in ["https", "http"]:
        try:
            r = await _client.get(f"{scheme}://{domain}", timeout=10)
            results["status"] = r.status_code
            results["final_url"] = str(r.url)
            results["server"] = r.headers.get("server", "?")
            results["powered_by"] = r.headers.get("x-powered-by", "?")
            results["content_type"] = r.headers.get("content-type", "?")

            # Tech detection from headers and body
            body = r.text[:5000].lower()
            tech = []
            if "wordpress" in body or "wp-content" in body:
                tech.append("WordPress")
            if "react" in body or "reactdom" in body or "__next" in body:
                tech.append("React/Next.js")
            if "vue" in body:
                tech.append("Vue.js")
            if "angular" in body:
                tech.append("Angular")
            if "jquery" in body:
                tech.append("jQuery")
            if "bootstrap" in body:
                tech.append("Bootstrap")
            if "cloudflare" in r.headers.get("server", "").lower():
                tech.append("Cloudflare")
            if r.headers.get("x-powered-by", ""):
                tech.append(r.headers["x-powered-by"])
            if "laravel" in body or "laravel" in str(r.headers):
                tech.append("Laravel")
            if "django" in body or "csrfmiddlewaretoken" in body:
                tech.append("Django")
            if "express" in r.headers.get("x-powered-by", "").lower():
                tech.append("Express.js")
            if "php" in r.headers.get("x-powered-by", "").lower():
                tech.append("PHP")
            if r.headers.get("x-aspnet-version"):
                tech.append(f"ASP.NET {r.headers['x-aspnet-version']}")
            results["technologies"] = tech

            # Security headers check
            sec = {}
            for h in ["content-security-policy", "x-frame-options", "x-content-type-options",
                       "strict-transport-security", "x-xss-protection", "referrer-policy"]:
                sec[h] = r.headers.get(h, "MISSING")
            results["security_headers"] = sec

            # Cookie analysis
            cookies = []
            for cookie in r.cookies.jar:
                flags = []
                if cookie.secure:
                    flags.append("Secure")
                if "httponly" in str(cookie).lower():
                    flags.append("HttpOnly")
                if "samesite" in str(cookie).lower():
                    flags.append("SameSite")
                cookies.append({"name": cookie.name, "flags": flags})
            results["cookies"] = cookies

            break
        except Exception:
            continue

    # IP geolocation
    if results.get("ips"):
        try:
            r = await _client.get(f"http://ip-api.com/json/{results['ips'][0]}")
            if r.status_code == 200:
                geo = r.json()
                results["hosting"] = {
                    "isp": geo.get("isp"),
                    "org": geo.get("org"),
                    "country": geo.get("country"),
                    "city": geo.get("city"),
                }
        except Exception:
            pass

    return results


async def web_scan(url: str) -> Dict:
    """Scan a website for common vulnerabilities and misconfigurations."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    results = {"url": url, "findings": []}

    try:
        r = await _client.get(url, timeout=15)
        body = r.text
        headers = r.headers

        # 1. Information disclosure in headers
        if headers.get("server"):
            results["findings"].append({
                "severity": "LOW",
                "type": "Information Disclosure",
                "detail": f"Server header exposes: {headers['server']}",
            })
        if headers.get("x-powered-by"):
            results["findings"].append({
                "severity": "LOW",
                "type": "Information Disclosure",
                "detail": f"X-Powered-By exposes: {headers['x-powered-by']}",
            })

        # 2. Missing security headers
        critical_headers = {
            "content-security-policy": "Content-Security-Policy",
            "x-frame-options": "X-Frame-Options (clickjacking risk)",
            "strict-transport-security": "HSTS (downgrade attack risk)",
            "x-content-type-options": "X-Content-Type-Options (MIME sniffing)",
        }
        for h, desc in critical_headers.items():
            if not headers.get(h):
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "Missing Security Header",
                    "detail": f"Missing {desc}",
                })

        # 3. Cookie security issues
        for cookie in r.cookies.jar:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            cookie_str = str(cookie).lower()
            if "httponly" not in cookie_str:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_str:
                issues.append("missing SameSite flag")
            if issues:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "Insecure Cookie",
                    "detail": f"Cookie '{cookie.name}': {', '.join(issues)}",
                })

        # 4. Sensitive info in HTML
        patterns = [
            (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[\w-]{20,}', "API key exposed in source"),
            (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']+', "Password in source code"),
            (r'(?i)(?:secret|token)\s*[:=]\s*["\'][\w-]{10,}', "Secret/Token in source"),
            (r'(?i)(?:aws_access_key_id|AKIA)\s*[:=]?\s*["\']?[A-Z0-9]{16,}', "AWS key in source"),
            (r'<!--.*?(?:TODO|FIXME|HACK|password|admin|debug).*?-->', "Sensitive HTML comment"),
        ]
        for pattern, desc in patterns:
            matches = re.findall(pattern, body[:20000])
            if matches:
                results["findings"].append({
                    "severity": "HIGH",
                    "type": "Sensitive Data Exposure",
                    "detail": f"{desc}: found {len(matches)} instance(s)",
                    "sample": matches[0][:100],
                })

        # 5. Email/phone PII leaks
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
        phones = re.findall(r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', body)
        if emails:
            unique_emails = list(set(emails))[:10]
            results["findings"].append({
                "severity": "MEDIUM",
                "type": "PII Exposure — Emails",
                "detail": f"Found {len(unique_emails)} email(s) on page",
                "data": unique_emails,
            })
        if phones:
            unique_phones = list(set(phones))[:10]
            results["findings"].append({
                "severity": "MEDIUM",
                "type": "PII Exposure — Phone Numbers",
                "detail": f"Found {len(unique_phones)} phone number(s) on page",
                "data": unique_phones,
            })

        # 6. Form analysis
        forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
        for i, form in enumerate(forms):
            has_csrf = bool(re.search(r'csrf|_token|authenticity_token', form, re.IGNORECASE))
            action = re.search(r'action=["\']([^"\']*)', form)
            method = re.search(r'method=["\']([^"\']*)', form, re.IGNORECASE)
            if not has_csrf:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "Missing CSRF Token",
                    "detail": f"Form #{i+1} has no CSRF protection (action: {action.group(1) if action else 'self'})",
                })
            password_fields = re.findall(r'type=["\']password', form, re.IGNORECASE)
            if password_fields and method and method.group(1).upper() == "GET":
                results["findings"].append({
                    "severity": "HIGH",
                    "type": "Password via GET",
                    "detail": f"Form #{i+1} sends password over GET method",
                })

        # 7. Mixed content check
        if url.startswith("https://"):
            http_resources = re.findall(r'(?:src|href)=["\']http://', body, re.IGNORECASE)
            if http_resources:
                results["findings"].append({
                    "severity": "LOW",
                    "type": "Mixed Content",
                    "detail": f"HTTPS page loads {len(http_resources)} HTTP resource(s)",
                })

    except Exception as e:
        results["error"] = str(e)

    return results


async def dir_scan(url: str) -> Dict:
    """Check for common exposed files and directories."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    paths = [
        "/.env", "/.git/config", "/.git/HEAD", "/.gitignore",
        "/robots.txt", "/sitemap.xml", "/.htaccess", "/server-status",
        "/wp-admin/", "/wp-login.php", "/admin/", "/admin/login",
        "/administrator/", "/phpmyadmin/", "/_phpinfo.php", "/phpinfo.php",
        "/info.php", "/api/", "/api/v1/", "/graphql",
        "/swagger.json", "/api-docs", "/openapi.json",
        "/.well-known/security.txt", "/security.txt",
        "/backup/", "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
        "/config.php", "/config.yml", "/config.json", "/settings.json",
        "/.DS_Store", "/Thumbs.db", "/web.config",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.txt",
        "/.svn/entries", "/.svn/wc.db",
        "/debug/", "/debug.log", "/error.log", "/access.log",
        "/console", "/actuator", "/actuator/health", "/actuator/env",
        "/.aws/credentials", "/etc/passwd",
        "/login", "/signup", "/register",
        "/xmlrpc.php", "/wp-json/wp/v2/users",
    ]

    found = []
    import asyncio

    async def check_path(path):
        try:
            r = await _client.get(url + path, timeout=8, follow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                size = len(r.content) if r.status_code == 200 else 0
                return {
                    "path": path,
                    "status": r.status_code,
                    "size": size,
                    "interesting": r.status_code == 200 and size > 0,
                }
        except Exception:
            pass
        return None

    # Run in batches of 10 to avoid overwhelming
    for i in range(0, len(paths), 10):
        batch = paths[i:i+10]
        tasks = [check_path(p) for p in batch]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                found.append(r)

    return {"url": url, "files_found": found, "total_checked": len(paths)}


async def whois_lookup(domain: str) -> str:
    """WHOIS-style lookup via free API."""
    try:
        r = await _client.get(
            f"https://api.api-ninjas.com/v1/whois?domain={domain}",
            headers={"X-Api-Key": "free"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            lines = []
            for k, v in data.items():
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v)
                lines.append(f"{k}: {v}")
            return "\n".join(lines) if lines else "No WHOIS data"
        return f"WHOIS lookup failed ({r.status_code})"
    except Exception as e:
        return f"WHOIS error: {str(e)}"


async def shodan_search(query: str) -> str:
    """Search Shodan via their free facets endpoint."""
    try:
        # Use the free Shodan internetdb for IP lookups
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
            r = await _client.get(f"https://internetdb.shodan.io/{query}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                lines = [f"IP: {data.get('ip', query)}"]
                if data.get("ports"):
                    lines.append(f"Open Ports: {', '.join(str(p) for p in data['ports'])}")
                if data.get("hostnames"):
                    lines.append(f"Hostnames: {', '.join(data['hostnames'])}")
                if data.get("cpes"):
                    lines.append(f"CPEs: {', '.join(data['cpes'][:5])}")
                if data.get("vulns"):
                    lines.append(f"Vulns: {', '.join(data['vulns'][:10])}")
                if data.get("tags"):
                    lines.append(f"Tags: {', '.join(data['tags'])}")
                return "\n".join(lines)
            return f"No Shodan data for {query}"

        # If it's a domain, resolve to IP first
        try:
            ips = socket.getaddrinfo(query, None)
            ip = list(set(addr[4][0] for addr in ips))[0]
            return await shodan_search(ip)
        except Exception:
            return f"Could not resolve {query}"
    except Exception as e:
        return f"Shodan error: {str(e)}"


async def ssl_check(domain: str) -> Dict:
    """Check SSL/TLS certificate details."""
    import ssl as _ssl
    import datetime
    results = {"domain": domain}
    try:
        ctx = _ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                results["subject"] = dict(x[0] for x in cert.get("subject", []))
                results["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                results["serial"] = cert.get("serialNumber", "?")
                results["not_before"] = cert.get("notBefore", "?")
                results["not_after"] = cert.get("notAfter", "?")
                results["version"] = ssock.version()
                san = cert.get("subjectAltName", [])
                results["alt_names"] = [x[1] for x in san]

                # Check expiry
                expire = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expire - datetime.datetime.utcnow()).days
                results["days_until_expiry"] = days_left
                results["expired"] = days_left < 0
    except Exception as e:
        results["error"] = str(e)
    return results


async def crawl_links(url: str) -> Dict:
    """Crawl a page and extract all links, emails, and interesting data."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    results = {"url": url}
    try:
        r = await _client.get(url, timeout=15)
        body = r.text

        # Extract links
        links = re.findall(r'href=["\']([^"\']+)', body)
        internal = []
        external = []
        for link in links:
            if link.startswith(("http://", "https://")):
                if url.split("/")[2] in link:
                    internal.append(link)
                else:
                    external.append(link)
            elif link.startswith("/"):
                internal.append(link)

        results["internal_links"] = list(set(internal))[:50]
        results["external_links"] = list(set(external))[:30]

        # Extract emails
        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)))
        results["emails"] = emails[:20]

        # Extract phones
        phones = list(set(re.findall(r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', body)))
        results["phones"] = phones[:20]

        # Extract social links
        socials = re.findall(
            r'https?://(?:www\.)?(?:facebook|twitter|instagram|linkedin|youtube|tiktok|github)\.com/[\w.-]+',
            body
        )
        results["social_links"] = list(set(socials))

        # JavaScript files (may contain API keys)
        js_files = list(set(re.findall(r'src=["\']([^"\']*\.js)["\']', body)))
        results["js_files"] = js_files[:20]

        # Extract comments
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        interesting = [c.strip() for c in comments if len(c.strip()) > 10]
        results["html_comments"] = interesting[:10]

    except Exception as e:
        results["error"] = str(e)
    return results
