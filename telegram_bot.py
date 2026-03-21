"""
Pocket Hacker - Telegram Bot Interface
Kali Linux AI in your pocket. Ethical hacking assistant via Telegram.
"""

import logging
import html
import json
from typing import Optional

from telegram import Update, BotCommand
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes, filters
)
from telegram.constants import ParseMode

from config import Config
from ai_brain import AIBrain
from tools import (
    base64_encode, base64_decode, hex_encode, hex_decode,
    url_encode, url_decode, rot13, binary_encode, binary_decode,
    morse_encode, morse_decode, generate_hashes, identify_hash,
    resolve_dns, ip_lookup, check_headers, search_cve,
    subnet_calc, get_ports_table, port_info,
    phone_lookup, email_osint, username_search, domain_recon,
    web_scan, dir_scan, whois_lookup, shodan_search, ssl_check,
    crawl_links,
)
from db import Database

logger = logging.getLogger(__name__)


def esc(text: str) -> str:
    return html.escape(str(text))


class TelegramBot:
    def __init__(self, config: Config):
        self.config = config
        self.db = Database()
        self.ai = AIBrain(config)
        self.app: Optional[Application] = None

    def _auth(self, uid: int) -> bool:
        if not self.config.authorized_users:
            return True
        return uid in self.config.authorized_users

    async def start(self):
        self.app = (
            Application.builder()
            .token(self.config.telegram_token)
            .build()
        )

        commands = [
            ("start", self.cmd_start),
            ("help", self.cmd_help),
            ("encode", self.cmd_encode),
            ("decode", self.cmd_decode),
            ("hash", self.cmd_hash),
            ("hashid", self.cmd_hashid),
            ("rot13", self.cmd_rot13),
            ("binary", self.cmd_binary),
            ("morse", self.cmd_morse),
            ("ip", self.cmd_ip),
            ("dns", self.cmd_dns),
            ("headers", self.cmd_headers),
            ("ports", self.cmd_ports),
            ("subnet", self.cmd_subnet),
            ("cve", self.cmd_cve),
            ("phone", self.cmd_phone),
            ("email", self.cmd_email),
            ("user", self.cmd_user),
            ("recon", self.cmd_recon),
            ("webscan", self.cmd_webscan),
            ("dirscan", self.cmd_dirscan),
            ("whois", self.cmd_whois),
            ("shodan", self.cmd_shodan),
            ("ssl", self.cmd_ssl),
            ("crawl", self.cmd_crawl),
            ("tool", self.cmd_tool),
            ("scan", self.cmd_scan),
            ("privesc", self.cmd_privesc),
            ("shells", self.cmd_shells),
            ("ctf", self.cmd_ctf),
            ("payload", self.cmd_payload),
            ("note", self.cmd_note),
            ("notes", self.cmd_notes),
            ("clear", self.cmd_clear),
            ("whoami", self.cmd_whoami),
        ]

        for name, handler in commands:
            self.app.add_handler(CommandHandler(name, handler))

        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))

        menu = [BotCommand(n, h.__doc__ or n) for n, h in commands[:20]]
        await self.app.bot.set_my_commands(menu)

        logger.info("🔓 Pocket Hacker bot started")
        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling(drop_pending_updates=True)

    async def stop(self):
        if self.app:
            await self.app.updater.stop()
            await self.app.stop()
            await self.app.shutdown()
        await self.ai.close()

    async def _send(self, update: Update, text: str, parse_mode=ParseMode.HTML):
        """Send a message, splitting if too long."""
        max_len = 4000
        if len(text) <= max_len:
            await update.message.reply_text(text, parse_mode=parse_mode)
            return
        # Split on newlines
        chunks = []
        current = ""
        for line in text.split("\n"):
            if len(current) + len(line) + 1 > max_len:
                chunks.append(current)
                current = line
            else:
                current += ("\n" if current else "") + line
        if current:
            chunks.append(current)
        for chunk in chunks:
            await update.message.reply_text(chunk, parse_mode=parse_mode)

    # ── Commands ──

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start the bot"""
        if not self._auth(update.effective_user.id):
            return
        text = """🔓 <b>POCKET HACKER</b> — Your Pocket Kali Linux

<b>🔍 OSINT (Real Lookups):</b>
/phone [number] — Phone number OSINT
/email [addr] — Email breach check + OSINT
/user [name] — Username search across 20+ sites
/recon [domain] — Full domain reconnaissance
/whois [domain] — WHOIS lookup
/shodan [ip/domain] — Shodan recon (open ports, vulns)
/crawl [url] — Crawl page for links, emails, data

<b>🛡️ Web Scanning (Real Scans):</b>
/webscan [url] — Vulnerability scan (headers, PII, secrets, cookies)
/dirscan [url] — Directory/file brute force (60+ paths)
/headers [url] — Security header analysis
/ssl [domain] — SSL/TLS certificate check
/cve [search] — CVE database search

<b>🔐 Crypto/Encoding:</b>
/encode /decode — Base64, Hex, URL, Binary
/hash [text] — Generate all hashes
/hashid [hash] — Identify hash type
/rot13 /binary /morse — Ciphers

<b>🌐 Network:</b>
/ip [target] — IP geolocation
/dns [domain] — DNS resolution
/ports [num] — Port reference
/subnet [CIDR] — Subnet calculator

<b>🤖 AI Hacking Assistant:</b>
/tool [name] — Cheat sheet for any tool
/scan [target] — Full recon methodology
/privesc [os] — Privilege escalation guide
/shells [type] — Reverse shell cheat sheet
/ctf [challenge] — CTF solving help
/payload [type] — Exploit/payload guidance

<b>📝 Other:</b>
/note /notes — Save & view notes
/clear — Clear chat history
/whoami — Your info

Or just type anything — full AI hacking chat 🧠"""
        await self._send(update, text)

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show commands"""
        if not self._auth(update.effective_user.id):
            return
        await self.cmd_start(update, context)

    # ── Encoding / Decoding ──

    async def cmd_encode(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Encode text (base64/hex/url)"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /encode [text]\nEncodes to base64, hex, and URL")
            return
        text = f"""🔐 <b>ENCODE:</b> <code>{esc(args)}</code>

<b>Base64:</b> <code>{esc(base64_encode(args))}</code>
<b>Hex:</b> <code>{esc(hex_encode(args))}</code>
<b>URL:</b> <code>{esc(url_encode(args))}</code>
<b>Binary:</b> <code>{esc(binary_encode(args))}</code>"""
        await self._send(update, text)

    async def cmd_decode(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Decode text (base64/hex/url)"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /decode [encoded_text]\nTries base64, hex, URL decode")
            return
        text = f"""🔓 <b>DECODE:</b> <code>{esc(args)}</code>

<b>Base64:</b> <code>{esc(base64_decode(args))}</code>
<b>Hex:</b> <code>{esc(hex_decode(args))}</code>
<b>URL:</b> <code>{esc(url_decode(args))}</code>
<b>ROT13:</b> <code>{esc(rot13(args))}</code>"""
        await self._send(update, text)

    async def cmd_hash(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Generate hashes of text"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /hash [text]")
            return
        hashes = generate_hashes(args)
        text = f"""#️⃣ <b>HASHES:</b> <code>{esc(args)}</code>

<b>MD5:</b>    <code>{hashes['MD5']}</code>
<b>SHA1:</b>   <code>{hashes['SHA1']}</code>
<b>SHA256:</b> <code>{hashes['SHA256']}</code>
<b>SHA512:</b> <code>{hashes['SHA512']}</code>"""
        await self._send(update, text)

    async def cmd_hashid(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Identify a hash type"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /hashid [hash]\nIdentifies the hash type")
            return
        result = identify_hash(args)
        # Also ask AI for deeper analysis
        ai_analysis = await self.ai.analyze_hash(args)
        text = f"""🔍 <b>HASH IDENTIFICATION</b>

<b>Hash:</b> <code>{esc(args)}</code>
<b>Length:</b> {len(args.strip())}
<b>Type:</b> {esc(result)}

{esc(ai_analysis)}"""
        await self._send(update, text)

    async def cmd_rot13(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """ROT13 encode/decode"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /rot13 [text]")
            return
        await self._send(update, f"🔄 <b>ROT13:</b> <code>{esc(rot13(args))}</code>")

    async def cmd_binary(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Binary encode/decode"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /binary [text or binary]")
            return
        if all(c in '01 ' for c in args):
            result = binary_decode(args)
            await self._send(update, f"📟 <b>Binary → Text:</b> <code>{esc(result)}</code>")
        else:
            result = binary_encode(args)
            await self._send(update, f"📟 <b>Text → Binary:</b> <code>{esc(result)}</code>")

    async def cmd_morse(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Morse code encode/decode"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /morse [text or morse code]")
            return
        if all(c in '.-/ ' for c in args):
            result = morse_decode(args)
            await self._send(update, f"📡 <b>Morse → Text:</b> <code>{esc(result)}</code>")
        else:
            result = morse_encode(args)
            await self._send(update, f"📡 <b>Text → Morse:</b> <code>{esc(result)}</code>")

    # ── Network Tools ──

    async def cmd_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """IP/domain geolocation lookup"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /ip [IP or domain]")
            return
        await update.message.reply_text("🔍 Looking up...")
        result = await ip_lookup(args)
        if "error" in result:
            await self._send(update, f"❌ {esc(result['error'])}")
            return
        text = f"""🌍 <b>IP LOOKUP:</b> {esc(args)}

<b>IP:</b> {esc(result.get('query', '?'))}
<b>ISP:</b> {esc(result.get('isp', '?'))}
<b>Org:</b> {esc(result.get('org', '?'))}
<b>AS:</b> {esc(result.get('as', '?'))}
<b>Country:</b> {esc(result.get('country', '?'))}
<b>Region:</b> {esc(result.get('regionName', '?'))}
<b>City:</b> {esc(result.get('city', '?'))}
<b>ZIP:</b> {esc(result.get('zip', '?'))}
<b>Lat/Lon:</b> {result.get('lat', '?')}, {result.get('lon', '?')}
<b>Timezone:</b> {esc(result.get('timezone', '?'))}"""
        await self._send(update, text)

    async def cmd_dns(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """DNS resolution lookup"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /dns [domain]")
            return
        result = resolve_dns(args)
        if "error" in result:
            await self._send(update, f"❌ {esc(result['error'])}")
            return
        ips = "\n".join(f"  • {ip}" for ip in result.get("ips", []))
        text = f"""🔎 <b>DNS LOOKUP:</b> {esc(args)}

<b>Resolved IPs:</b>
{ips}"""
        await self._send(update, text)

    async def cmd_headers(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check HTTP security headers"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /headers [url]")
            return
        await update.message.reply_text("🔍 Checking headers...")
        result = await check_headers(args)
        if "error" in result:
            await self._send(update, f"❌ {esc(result['error'])}")
            return
        sec = result["security_headers"]
        header_lines = "\n".join(f"  <b>{k}:</b> {esc(v)}" for k, v in sec.items())
        missing = sum(1 for v in sec.values() if "MISSING" in v)
        grade = "A" if missing == 0 else "B" if missing <= 2 else "C" if missing <= 4 else "F"
        text = f"""🛡️ <b>SECURITY HEADERS:</b> {esc(str(result['url']))}

<b>Status:</b> {result['status']}
<b>Server:</b> {esc(result['server'])}
<b>Powered By:</b> {esc(result['powered_by'])}
<b>Grade:</b> {grade} ({7-missing}/7 headers present)

<b>Security Headers:</b>
{header_lines}"""
        await self._send(update, text)

    async def cmd_ports(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Common port reference"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if args and args.isdigit():
            p = int(args)
            service = port_info(p)
            await self._send(update, f"🔌 Port <b>{p}</b>: {esc(service)}")
            return
        table = get_ports_table()
        await self._send(update, f"🔌 <b>COMMON PORTS</b>\n\n<pre>{esc(table)}</pre>")

    async def cmd_subnet(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Subnet calculator"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /subnet [CIDR]\nExample: /subnet 192.168.1.0/24")
            return
        result = subnet_calc(args)
        if "error" in result:
            await self._send(update, f"❌ {esc(result['error'])}")
            return
        text = f"""📐 <b>SUBNET CALCULATOR:</b> {esc(args)}

<b>Network:</b> {result['network']}
<b>Broadcast:</b> {result['broadcast']}
<b>Netmask:</b> {result['netmask']}
<b>Wildcard:</b> {result['hostmask']}
<b>Prefix:</b> /{result['prefix']}
<b>Usable Hosts:</b> {result['num_hosts']}
<b>First Host:</b> {result['first_host']}
<b>Last Host:</b> {result['last_host']}
<b>Private:</b> {'Yes' if result['is_private'] else 'No'}"""
        await self._send(update, text)

    async def cmd_cve(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Search CVE database"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /cve [search term]\nExample: /cve apache log4j")
            return
        await update.message.reply_text("🔍 Searching CVE database...")
        result = await search_cve(args)
        text = f"🛡️ <b>CVE SEARCH:</b> {esc(args)}\n\n{esc(result)}"
        await self._send(update, text)

    # ── OSINT Commands ──

    async def cmd_phone(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Phone number OSINT lookup"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /phone [number]\nExample: /phone +15551234567")
            return
        await update.message.reply_text("📱 Running phone OSINT...")
        result = await phone_lookup(args)
        # Also get AI analysis
        ai = await self.ai.chat(f"I ran a phone OSINT lookup on {args}. Results: {json.dumps(result, default=str)}. Analyze this and tell me what you can infer. Also suggest additional OSINT techniques I could use to find more info on this number.")
        lines = [f"📱 <b>PHONE OSINT:</b> {esc(args)}\n"]
        for k, v in result.items():
            if k != "phone" and v:
                lines.append(f"<b>{esc(k)}:</b> {esc(str(v)[:200])}")
        lines.append(f"\n🤖 <b>AI Analysis:</b>\n{esc(ai)}")
        await self._send(update, "\n".join(lines))

    async def cmd_email(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Email OSINT + breach check"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /email [address]\nChecks breaches, validates domain, etc.")
            return
        await update.message.reply_text("📧 Running email OSINT...")
        result = await email_osint(args)
        lines = [f"📧 <b>EMAIL OSINT:</b> {esc(args)}\n"]
        if result.get("breaches_found", 0) > 0:
            lines.append(f"🔴 <b>BREACHED!</b> Found in {result['breaches_found']} breach(es):\n")
            for b in result.get("breached_sites", []):
                data = ", ".join(b.get("data_exposed", [])[:5])
                lines.append(f"  • <b>{esc(b['name'])}</b> ({b['date']}) — {esc(data)}")
        else:
            lines.append("🟢 No known breaches found")
        if result.get("domain_valid") is not None:
            lines.append(f"\n<b>Domain valid:</b> {'Yes' if result['domain_valid'] else 'No'}")
        if result.get("domain"):
            lines.append(f"<b>Domain:</b> {esc(result['domain'])}")
        if result.get("pastes_found", 0) > 0:
            lines.append(f"📋 Found in {result['pastes_found']} paste(s)")
        await self._send(update, "\n".join(lines))

    async def cmd_user(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Username search across platforms"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /user [username]\nSearches 20+ platforms")
            return
        await update.message.reply_text(f"🔍 Searching for '{args}' across platforms...")
        result = await username_search(args)
        found = result.get("found", {})
        lines = [f"👤 <b>USERNAME SEARCH:</b> {esc(args)}\n"]
        if found:
            lines.append(f"✅ <b>Found on {len(found)} platform(s):</b>\n")
            for platform, url in found.items():
                lines.append(f"  • <b>{esc(platform)}:</b> {esc(url)}")
        else:
            lines.append("❌ Not found on any checked platforms")
        lines.append(f"\n📊 Checked {len(found) + len(result.get('not_found', []))} platforms total")
        await self._send(update, "\n".join(lines))

    async def cmd_recon(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Full domain reconnaissance"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /recon [domain]\nExample: /recon example.com")
            return
        await update.message.reply_text(f"🎯 Running full recon on {args}...")
        result = await domain_recon(args)
        lines = [f"🎯 <b>DOMAIN RECON:</b> {esc(args)}\n"]
        if result.get("ips"):
            lines.append(f"<b>IPs:</b> {', '.join(result['ips'])}")
        if result.get("server"):
            lines.append(f"<b>Server:</b> {esc(result['server'])}")
        if result.get("powered_by") and result['powered_by'] != '?':
            lines.append(f"<b>Powered By:</b> {esc(result['powered_by'])}")
        if result.get("technologies"):
            lines.append(f"<b>Tech Stack:</b> {', '.join(result['technologies'])}")
        if result.get("hosting"):
            h = result["hosting"]
            lines.append(f"<b>Hosting:</b> {esc(h.get('org', '?'))} ({esc(h.get('country', '?'))})")
        if result.get("security_headers"):
            missing = sum(1 for v in result["security_headers"].values() if v == "MISSING")
            total = len(result["security_headers"])
            lines.append(f"\n<b>Security Headers:</b> {total - missing}/{total} present")
            for h, v in result["security_headers"].items():
                icon = "✅" if v != "MISSING" else "❌"
                lines.append(f"  {icon} {h}")
        if result.get("cookies"):
            lines.append(f"\n<b>Cookies:</b> {len(result['cookies'])} found")
            for c in result["cookies"][:5]:
                flags = ", ".join(c["flags"]) if c["flags"] else "NO FLAGS"
                lines.append(f"  • {esc(c['name'])}: {flags}")
        await self._send(update, "\n".join(lines))

    async def cmd_webscan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Scan website for vulnerabilities"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /webscan [url]\nScans for vulns, PII leaks, misconfigs")
            return
        await update.message.reply_text(f"🛡️ Scanning {args} for vulnerabilities...")
        result = await web_scan(args)
        findings = result.get("findings", [])
        lines = [f"🛡️ <b>WEB VULNERABILITY SCAN:</b> {esc(args)}\n"]
        if not findings:
            lines.append("✅ No issues found (basic scan)")
        else:
            high = sum(1 for f in findings if f["severity"] == "HIGH")
            med = sum(1 for f in findings if f["severity"] == "MEDIUM")
            low = sum(1 for f in findings if f["severity"] == "LOW")
            lines.append(f"Found <b>{len(findings)}</b> issue(s): 🔴{high} HIGH  🟡{med} MED  🔵{low} LOW\n")
            for f in findings:
                sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(f["severity"], "⚪")
                lines.append(f"{sev_icon} <b>[{f['severity']}]</b> {esc(f['type'])}")
                lines.append(f"   {esc(f['detail'])}")
                if f.get("data"):
                    for item in f["data"][:5]:
                        lines.append(f"   → {esc(item)}")
                if f.get("sample"):
                    lines.append(f"   Sample: <code>{esc(f['sample'][:80])}</code>")
                lines.append("")
        # AI analysis of findings
        if findings:
            ai = await self.ai.chat(f"I scanned {args} and found these issues: {json.dumps(findings, default=str)[:2000]}. Give me a brief risk summary and suggest next steps for exploitation/further testing.")
            lines.append(f"🤖 <b>AI Analysis:</b>\n{esc(ai)}")
        await self._send(update, "\n".join(lines))

    async def cmd_dirscan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Brute force directories/files"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /dirscan [url]\nChecks 60+ common paths")
            return
        await update.message.reply_text(f"📂 Scanning directories on {args}... (checking 60+ paths)")
        result = await dir_scan(args)
        found = result.get("files_found", [])
        lines = [f"📂 <b>DIRECTORY SCAN:</b> {esc(args)}\n"]
        interesting = [f for f in found if f.get("interesting")]
        accessible = [f for f in found if f["status"] in (200, 301, 302)]
        forbidden = [f for f in found if f["status"] == 403]
        if interesting:
            lines.append(f"🔴 <b>{len(interesting)} ACCESSIBLE file(s)/dirs:</b>\n")
            for f in interesting:
                lines.append(f"  ✅ <b>{esc(f['path'])}</b> — {f['status']} ({f['size']} bytes)")
        if forbidden:
            lines.append(f"\n🟡 <b>{len(forbidden)} FORBIDDEN (exist but blocked):</b>\n")
            for f in forbidden[:15]:
                lines.append(f"  🚫 {esc(f['path'])} — 403")
        if not accessible and not forbidden:
            lines.append("✅ No exposed files/directories found")
        lines.append(f"\n📊 Checked {result['total_checked']} paths")
        await self._send(update, "\n".join(lines))

    async def cmd_whois(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """WHOIS domain lookup"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /whois [domain]")
            return
        await update.message.reply_text("🔍 WHOIS lookup...")
        result = await whois_lookup(args)
        await self._send(update, f"🌐 <b>WHOIS:</b> {esc(args)}\n\n<pre>{esc(result[:3000])}</pre>")

    async def cmd_shodan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Shodan recon (open ports, vulns)"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /shodan [IP or domain]\nChecks open ports, hostnames, known vulns")
            return
        await update.message.reply_text(f"🔍 Shodan lookup for {args}...")
        result = await shodan_search(args)
        await self._send(update, f"🌐 <b>SHODAN:</b> {esc(args)}\n\n{esc(result)}")

    async def cmd_ssl(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """SSL/TLS certificate check"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /ssl [domain]")
            return
        await update.message.reply_text(f"🔒 Checking SSL for {args}...")
        result = await ssl_check(args)
        if "error" in result:
            await self._send(update, f"❌ SSL Error: {esc(result['error'])}")
            return
        lines = [f"🔒 <b>SSL/TLS:</b> {esc(args)}\n"]
        if result.get("subject"):
            lines.append(f"<b>Subject:</b> {esc(str(result['subject']))}")
        if result.get("issuer"):
            issuer = result['issuer']
            lines.append(f"<b>Issuer:</b> {esc(issuer.get('organizationName', str(issuer)))}")
        if result.get("version"):
            lines.append(f"<b>Protocol:</b> {esc(result['version'])}")
        if result.get("not_after"):
            lines.append(f"<b>Expires:</b> {esc(result['not_after'])}")
        if result.get("days_until_expiry") is not None:
            days = result["days_until_expiry"]
            icon = "🟢" if days > 30 else "🟡" if days > 0 else "🔴"
            lines.append(f"{icon} <b>{days} days until expiry</b>")
        if result.get("alt_names"):
            lines.append(f"<b>Alt Names:</b> {', '.join(result['alt_names'][:10])}")
        await self._send(update, "\n".join(lines))

    async def cmd_crawl(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Crawl page for links, emails, data"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /crawl [url]\nExtracts links, emails, phones, JS files, comments")
            return
        await update.message.reply_text(f"🕷️ Crawling {args}...")
        result = await crawl_links(args)
        lines = [f"🕷️ <b>CRAWL RESULTS:</b> {esc(args)}\n"]
        if result.get("emails"):
            lines.append(f"📧 <b>Emails ({len(result['emails'])}):</b>")
            for e in result["emails"][:10]:
                lines.append(f"  • {esc(e)}")
        if result.get("phones"):
            lines.append(f"\n📱 <b>Phone Numbers ({len(result['phones'])}):</b>")
            for p in result["phones"][:10]:
                lines.append(f"  • {esc(p)}")
        if result.get("social_links"):
            lines.append(f"\n🔗 <b>Social Media:</b>")
            for s in result["social_links"][:10]:
                lines.append(f"  • {esc(s)}")
        if result.get("js_files"):
            lines.append(f"\n📜 <b>JavaScript Files ({len(result['js_files'])}):</b>")
            for j in result["js_files"][:10]:
                lines.append(f"  • {esc(j)}")
        if result.get("html_comments"):
            lines.append(f"\n💬 <b>HTML Comments ({len(result['html_comments'])}):</b>")
            for c in result["html_comments"][:5]:
                lines.append(f"  • <code>{esc(c[:150])}</code>")
        lines.append(f"\n<b>Internal Links:</b> {len(result.get('internal_links', []))}")
        lines.append(f"<b>External Links:</b> {len(result.get('external_links', []))}")
        await self._send(update, "\n".join(lines))

    # ── AI Hacking Commands ──

    async def cmd_tool(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Cheat sheet for any hacking tool"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, """Usage: /tool [tool name]
Examples: /tool nmap, /tool burpsuite, /tool metasploit, /tool sqlmap, /tool hydra, /tool hashcat, /tool gobuster, /tool ffuf, /tool john, /tool aircrack""")
            return
        await update.message.reply_text(f"📖 Loading {args} cheat sheet...")
        result = await self.ai.explain_tool(args)
        await self._send(update, f"🔧 <b>{esc(args.upper())} CHEAT SHEET</b>\n\n{esc(result)}")

    async def cmd_scan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Recon methodology for a target"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /scan [target description]\nExample: /scan web app on 10.10.10.1")
            return
        await update.message.reply_text("🎯 Building recon plan...")
        result = await self.ai.analyze_target(args)
        await self._send(update, f"🎯 <b>RECON PLAN</b>\n\n{esc(result)}")

    async def cmd_privesc(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Privilege escalation checklist"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        os_type = args if args else "linux"
        await update.message.reply_text(f"⬆️ Loading {os_type} privesc checklist...")
        result = await self.ai.privesc_help(os_type)
        await self._send(update, f"⬆️ <b>PRIVESC — {esc(os_type.upper())}</b>\n\n{esc(result)}")

    async def cmd_shells(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Reverse shell cheat sheet"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else "all"
        await update.message.reply_text("🐚 Loading reverse shells...")
        result = await self.ai.reverse_shell(args)
        await self._send(update, f"🐚 <b>REVERSE SHELLS</b>\n\n{esc(result)}")

    async def cmd_ctf(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """CTF challenge solving help"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /ctf [challenge description or data]")
            return
        await update.message.reply_text("🏴 Analyzing CTF challenge...")
        result = await self.ai.ctf_help(args)
        await self._send(update, f"🏴 <b>CTF HELP</b>\n\n{esc(result)}")

    async def cmd_payload(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Security testing guidance"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, """Usage: /payload [type] [details]
Examples:
/payload sqli login form
/payload xss search parameter
/payload ssrf internal network
/payload lfi file read""")
            return
        parts = args.split(None, 1)
        target_type = parts[0]
        details = parts[1] if len(parts) > 1 else ""
        await update.message.reply_text("⚡ Generating testing guidance...")
        result = await self.ai.generate_payload(target_type, details)
        await self._send(update, f"⚡ <b>TESTING GUIDE</b>\n\n{esc(result)}")

    # ── Notes ──

    async def cmd_note(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Save a note"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            await self._send(update, "Usage: /note [text to save]")
            return
        title = args[:50]
        note_id = self.db.save_note(update.effective_user.id, title, args)
        await self._send(update, f"📝 Note saved (#{note_id})")

    async def cmd_notes(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """View saved notes"""
        if not self._auth(update.effective_user.id):
            return
        notes = self.db.get_notes(update.effective_user.id)
        if not notes:
            await self._send(update, "📝 No notes saved. Use /note [text] to save one.")
            return
        lines = []
        for n in notes[:20]:
            lines.append(f"#{n['id']} — {esc(n['title'])}")
        await self._send(update, f"📝 <b>YOUR NOTES</b>\n\n" + "\n".join(lines))

    async def cmd_clear(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Clear conversation history"""
        if not self._auth(update.effective_user.id):
            return
        self.db.clear_conversation(update.effective_user.id)
        await self._send(update, "🗑️ Conversation history cleared.")

    async def cmd_whoami(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show your info"""
        if not self._auth(update.effective_user.id):
            return
        u = update.effective_user
        text = f"""👤 <b>WHOAMI</b>

<b>User ID:</b> {u.id}
<b>Username:</b> @{esc(u.username or 'none')}
<b>Name:</b> {esc(u.first_name or '')} {esc(u.last_name or '')}
<b>Bot:</b> Pocket Hacker v1.0
<b>AI Backend:</b> {self.ai.backend}
<b>Model:</b> {esc(self.config.groq_model)}"""
        await self._send(update, text)

    # ── Free-form Chat ──

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle any text — route to AI."""
        if not self._auth(update.effective_user.id):
            return
        uid = update.effective_user.id
        message = update.message.text.strip()
        if not message:
            return

        self.db.save_message(uid, "user", message)
        history = self.db.get_conversation(uid, limit=10)
        response = await self.ai.chat(message, history)
        self.db.save_message(uid, "assistant", response)
        await self._send(update, esc(response))
