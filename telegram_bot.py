"""
Pocket Flipper - Telegram Bot Interface
Your pocket Flipper Zero + Raspberry Pi hardware hacking toolkit via Telegram.
"""

import logging
import html
import json
import re
from typing import Optional

from telegram import Update, BotCommand
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes, filters
)
from telegram.constants import ParseMode

from config import Config
from ai_brain import AIBrain
from flipper_tools import (
    generate_duckyscript, list_badusb_payloads, BADUSB_TEMPLATES,
    rfid_info, generate_nfc_file, generate_rfid_file, mifare_keys, calc_uid_checksum,
    subghz_info, generate_sub_file, subghz_bruteforce,
    generate_ir_file, ir_protocols,
    generate_deauth_script, generate_evil_portal, generate_beacon_flood,
    generate_wifi_pineapple_setup,
    ble_spam_info, generate_ble_spam_script,
    rpi_gpio_pinout, rpi_hid_attack_script, rpi_wardriving_setup, rpi_packet_sniffer,
    ibutton_info, generate_ibutton_file,
    flipper_firmware_info, flipper_file_structure, frequency_info, jamming_info,
    flipper_generate,
    car_key_lookup, car_key_list, iphone_ble_scanner, iphone_nfc_read, signal_scan_guide,
    CAR_KEY_DB,
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
            ("badusb", self.cmd_badusb),
            ("rfid", self.cmd_rfid),
            ("nfc", self.cmd_nfc),
            ("subghz", self.cmd_subghz),
            ("ir", self.cmd_ir),
            ("ibutton", self.cmd_ibutton),
            ("mifare", self.cmd_mifare),
            ("genfile", self.cmd_genfile),
            ("firmware", self.cmd_firmware),
            ("flipper", self.cmd_flipper),
            ("freq", self.cmd_freq),
            ("deauth", self.cmd_deauth),
            ("evilportal", self.cmd_evilportal),
            ("ble", self.cmd_ble),
            ("wardrive", self.cmd_wardrive),
            ("sniffer", self.cmd_sniffer),
            ("hidattack", self.cmd_hidattack),
            ("gpio", self.cmd_gpio),
            ("carscan", self.cmd_carscan),
            ("signal", self.cmd_signal),
            ("bluescan", self.cmd_bluescan),
        ]

        for name, handler in commands:
            self.app.add_handler(CommandHandler(name, handler))

        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))

        menu = [BotCommand(n, h.__doc__ or n) for n, h in commands[:20]]
        await self.app.bot.set_my_commands(menu)

        logger.info("Pocket Flipper bot started")
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
        max_len = 4000
        if len(text) <= max_len:
            await update.message.reply_text(text, parse_mode=parse_mode)
            return
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

    # -- Commands --

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start the bot"""
        if not self._auth(update.effective_user.id):
            return
        text = """<b>POCKET FLIPPER</b> -- Your Flipper Zero in Telegram

<b>BADUSB / DUCKYSCRIPT:</b>
/badusb [name] -- Generate BadUSB/DuckyScript payloads
/hidattack -- RPi Zero USB HID attack

<b>RFID / NFC:</b>
/rfid [protocol] -- RFID protocol info and file gen
/nfc [uid] -- Generate NFC (.nfc) files
/mifare -- MIFARE Classic default keys
/ibutton [uid] -- iButton key file gen

<b>SUB-GHZ / RF:</b>
/subghz [protocol] -- Sub-GHz protocol DB and .sub files
/freq [mhz] -- RF frequency lookup
/genfile [type] [uid] -- Generate any Flipper file

<b>INFRARED:</b>
/ir [device] -- IR universal remote (.ir files)

<b>WIRELESS ATTACKS:</b>
/deauth [bssid] -- WiFi deauth script
/evilportal [ssid] -- Evil twin captive portal
/ble [type] -- BLE spam attack scripts
/wardrive -- RPi wardriving setup
/sniffer -- Network packet sniffer
/gpio -- Raspberry Pi GPIO pinout

<b>iPHONE SIGNAL SCANNER:</b>
/carscan [make] -- Car key frequency lookup (22+ vehicles)
/signal -- Full signal scanning guide (iPhone + hardware)
/bluescan -- iPhone BLE scanner setup (detect key fobs)

<b>FLIPPER SETUP:</b>
/firmware -- Flipper firmware options (Unleashed, Momentum)
/flipper -- Flipper SD card file structure

Or just type anything -- AI hardware hacking assistant"""
        await self._send(update, text)

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show commands"""
        if not self._auth(update.effective_user.id):
            return
        await self.cmd_start(update, context)

    # -- Flipper Zero / Hardware Commands --

    async def cmd_badusb(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Generate BadUSB/DuckyScript payload"""
        if not self._auth(update.effective_user.id):
            return
        args = context.args if context.args else []
        if not args or args[0].lower() == "list":
            await self._send(update, esc(list_badusb_payloads()))
            return
        template = args[0].lower()
        lhost = args[1] if len(args) > 1 else "ATTACKER_IP"
        lport = args[2] if len(args) > 2 else "4444"
        if template not in BADUSB_TEMPLATES:
            await self._send(update, f"Unknown payload: {esc(template)}\n\n" + esc(list_badusb_payloads()))
            return
        script = generate_duckyscript(template, lhost=lhost, lport=lport)
        info = BADUSB_TEMPLATES[template]
        text = f"BadUSB: <b>{esc(info['name'])}</b>\n{esc(info['desc'])}\n\n<pre>{esc(script)}</pre>\n\nSave as .txt on Flipper SD: /badusb/"
        await self._send(update, text)

    async def cmd_rfid(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """RFID protocol info"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        result = rfid_info(args)
        await self._send(update, f"<pre>{esc(result)}</pre>")

    async def cmd_nfc(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Generate Flipper NFC file"""
        if not self._auth(update.effective_user.id):
            return
        args = context.args if context.args else []
        if not args:
            await self._send(update, "Usage: /nfc [UID] [protocol]\nExample: /nfc DE:AD:BE:EF mifare_classic_1k")
            return
        uid = args[0]
        proto = args[1] if len(args) > 1 else "mifare_classic_1k"
        nfc_file = generate_nfc_file(uid, proto)
        text = f"NFC File Generated\n\n<pre>{esc(nfc_file[:2000])}</pre>\n\nSave as .nfc on Flipper SD: /nfc/"
        await self._send(update, text)

    async def cmd_subghz(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Sub-GHz protocol info"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if args and args.lower().startswith("brute"):
            parts = args.split()
            proto = parts[1] if len(parts) > 1 else "came"
            result = subghz_bruteforce(proto)
        elif args:
            result = subghz_info(args)
        else:
            result = subghz_info()
        await self._send(update, f"<pre>{esc(result)}</pre>")

    async def cmd_ir(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Generate IR universal remote file"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if args.lower() == "info":
            result = ir_protocols()
            await self._send(update, f"<pre>{esc(result)}</pre>")
            return
        ir_file = generate_ir_file(args)
        label = args if args else "Universal (ALL devices)"
        text = f"IR Remote: <b>{esc(label)}</b>\n\n<pre>{esc(ir_file[:3000])}</pre>\n\nSave as .ir on Flipper SD: /infrared/"
        await self._send(update, text)

    async def cmd_deauth(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Generate WiFi deauth script"""
        if not self._auth(update.effective_user.id):
            return
        args = context.args if context.args else []
        bssid = args[0] if args else "FF:FF:FF:FF:FF:FF"
        channel = args[1] if len(args) > 1 else "1"
        script = generate_deauth_script(bssid, channel)
        text = f"WiFi Deauth Script\nTarget: {esc(bssid)} Ch:{channel}\n\n<pre>{esc(script)}</pre>"
        await self._send(update, text)

    async def cmd_evilportal(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Generate evil twin captive portal"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else "Free_WiFi"
        result = generate_evil_portal(args)
        await self._send(update, f"<pre>{esc(result[:4000])}</pre>")

    async def cmd_ble(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """BLE spam attack info"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if args:
            script = generate_ble_spam_script(args)
            await self._send(update, f"<pre>{esc(script)}</pre>")
        else:
            await self._send(update, f"<pre>{esc(ble_spam_info())}</pre>")

    async def cmd_gpio(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Raspberry Pi GPIO pinout"""
        if not self._auth(update.effective_user.id):
            return
        await self._send(update, f"<pre>{esc(rpi_gpio_pinout())}</pre>")

    async def cmd_hidattack(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """RPi Zero USB HID attack"""
        if not self._auth(update.effective_user.id):
            return
        await self._send(update, f"<pre>{esc(rpi_hid_attack_script()[:4000])}</pre>")

    async def cmd_wardrive(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """RPi wardriving setup"""
        if not self._auth(update.effective_user.id):
            return
        await self._send(update, f"<pre>{esc(rpi_wardriving_setup()[:4000])}</pre>")

    async def cmd_sniffer(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Network packet sniffer"""
        if not self._auth(update.effective_user.id):
            return
        await self._send(update, f"<pre>{esc(rpi_packet_sniffer()[:4000])}</pre>")

    async def cmd_ibutton(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """iButton key info"""
        if not self._auth(update.effective_user.id):
            return
        args = context.args if context.args else []
        if not args:
            await self._send(update, f"<pre>{esc(ibutton_info())}</pre>")
            return
        uid = args[0]
        proto = args[1] if len(args) > 1 else "ds1990a"
        ibtn = generate_ibutton_file(uid, proto)
        text = f"iButton File\n\n<pre>{esc(ibtn)}</pre>\n\nSave as .ibtn on Flipper SD: /ibutton/"
        await self._send(update, text)

    async def cmd_firmware(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Flipper Zero firmware options"""
        if not self._auth(update.effective_user.id):
            return
        await self._send(update, f"<pre>{esc(flipper_firmware_info())}</pre>")

    async def cmd_flipper(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Flipper Zero SD card structure"""
        if not self._auth(update.effective_user.id):
            return
        await self._send(update, f"<pre>{esc(flipper_file_structure())}</pre>")

    async def cmd_freq(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """RF frequency lookup"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        result = frequency_info(args)
        await self._send(update, f"<pre>{esc(result)}</pre>")

    async def cmd_mifare(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """MIFARE Classic default keys"""
        if not self._auth(update.effective_user.id):
            return
        await self._send(update, f"<pre>{esc(mifare_keys())}</pre>")

    async def cmd_genfile(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Generate any Flipper file"""
        if not self._auth(update.effective_user.id):
            return
        args = context.args if context.args else []
        if not args:
            await self._send(update, "Usage: /genfile [type] [uid] [protocol]\nTypes: nfc, rfid, sub, ir, ibtn, badusb\nExample: /genfile nfc DE:AD:BE:EF mifare_classic_1k")
            return
        ftype = args[0]
        uid = args[1] if len(args) > 1 else "DE AD BE EF"
        proto = args[2] if len(args) > 2 else ""
        kwargs = {"uid": uid}
        if proto:
            kwargs["protocol"] = proto
        result = flipper_generate(ftype, **kwargs)
        text = f"Flipper <b>{esc(ftype.upper())}</b> File\n\n<pre>{esc(result[:3000])}</pre>"
        await self._send(update, text)

    # -- iPhone Signal Scanner --

    async def cmd_carscan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Car key frequency lookup"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args) if context.args else ""
        if not args:
            text = f"<pre>{esc(car_key_list()[:3500])}</pre>"
        else:
            text = f"<pre>{esc(car_key_lookup(args)[:3500])}</pre>"
        await self._send(update, text)

    async def cmd_signal(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Signal scanning guide"""
        if not self._auth(update.effective_user.id):
            return
        text = f"<pre>{esc(signal_scan_guide()[:3500])}</pre>"
        await self._send(update, text)

    async def cmd_bluescan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """iPhone BLE scanner setup"""
        if not self._auth(update.effective_user.id):
            return
        args = " ".join(context.args).lower() if context.args else ""
        if "nfc" in args:
            text = f"<pre>{esc(iphone_nfc_read()[:3500])}</pre>"
        else:
            text = f"<pre>{esc(iphone_ble_scanner()[:3500])}</pre>"
        await self._send(update, text)

    # -- Free-form Chat --

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle any text -- auto-detect hardware/flipper intent, then route to AI."""
        if not self._auth(update.effective_user.id):
            return
        uid = update.effective_user.id
        message = update.message.text.strip()
        if not message:
            return

        self.db.save_message(uid, "user", message)
        msg_lower = message.lower()

        # -- Auto-intent detection for hardware topics --
        tool_results = ""
        auto_ran = False

        # BadUSB / DuckyScript intent
        if any(w in msg_lower for w in ("badusb", "ducky", "rubber ducky", "hid attack", "usb payload", "keystroke injection")):
            auto_ran = True
            tmatch = None
            for tname in BADUSB_TEMPLATES:
                if tname.replace("_", " ") in msg_lower or tname in msg_lower:
                    tmatch = tname
                    break
            if tmatch:
                script = generate_duckyscript(tmatch)
                info = BADUSB_TEMPLATES[tmatch]
                tool_results += f"\nBADUSB: {info['name']}\n{script}\n"
            else:
                tool_results += f"\nBADUSB PAYLOADS:\n{list_badusb_payloads()}\n"

        # RFID/NFC intent
        if any(w in msg_lower for w in ("rfid", "nfc", "mifare", "ntag", "em4100", "hid prox", "proximity card", "clone card", "card clone")):
            auto_ran = True
            uid_match = re.search(r'([0-9A-Fa-f]{2}[:- ]){3,}[0-9A-Fa-f]{2}', message)
            if uid_match:
                uid_val = uid_match.group(0)
                tool_results += f"\nUID ANALYSIS:\n{calc_uid_checksum(uid_val)}\n"
                if "mifare" in msg_lower or "nfc" in msg_lower:
                    nfc = generate_nfc_file(uid_val)
                    tool_results += f"\nNFC FILE:\n{nfc[:1000]}\n"
                else:
                    rfid = generate_rfid_file(uid_val)
                    tool_results += f"\nRFID FILE:\n{rfid}\n"
            elif "mifare" in msg_lower and "key" in msg_lower:
                tool_results += f"\n{mifare_keys()}\n"
            else:
                proto = ""
                for p in ("em4100", "hid_prox", "t5577", "mifare_classic", "ntag215", "ntag216", "felica", "iclass"):
                    if p.replace("_", " ") in msg_lower or p in msg_lower:
                        proto = p
                        break
                tool_results += f"\n{rfid_info(proto)}\n"

        # Sub-GHz intent
        if any(w in msg_lower for w in ("sub-ghz", "subghz", "sub ghz", "garage", "gate remote", "433", "315 mhz", "rolling code", "brute force remote")):
            auto_ran = True
            if "brute" in msg_lower:
                proto = "came"
                for p in ("came", "nice_flo", "princeton", "linear", "chamberlain", "gate_tx"):
                    if p.replace("_", " ") in msg_lower or p in msg_lower:
                        proto = p
                        break
                tool_results += f"\n{subghz_bruteforce(proto)}\n"
            else:
                proto = ""
                for p in ("princeton", "keeloq", "came", "nice", "somfy", "linear", "chamberlain", "hormann", "faac", "bft"):
                    if p in msg_lower:
                        proto = p
                        break
                tool_results += f"\n{subghz_info(proto)}\n"

        # IR / remote control intent
        if any(w in msg_lower for w in ("infrared", "ir remote", "universal remote", "tv remote", "ir blaster")) and not auto_ran:
            auto_ran = True
            device = "tv"
            for d in ("tv", "ac", "projector", "soundbar", "fan", "led_strip", "apple_tv"):
                if d.replace("_", " ") in msg_lower:
                    device = d
                    break
            ir_file = generate_ir_file(device)
            tool_results += f"\nIR REMOTE ({device}):\n{ir_file[:2000]}\n"

        # WiFi attack intent
        if any(w in msg_lower for w in ("deauth", "evil twin", "evil portal", "captive portal", "beacon flood", "wifi attack", "wifi hack", "pineapple")):
            auto_ran = True
            if "evil" in msg_lower or "captive" in msg_lower or "portal" in msg_lower:
                ssid_match = re.search(r'(?:ssid|name|called)\s+["\']?(\S+)["\']?', msg_lower)
                ssid = ssid_match.group(1) if ssid_match else "Free_WiFi"
                tool_results += f"\n{generate_evil_portal(ssid)[:3000]}\n"
            elif "beacon" in msg_lower or "flood" in msg_lower:
                tool_results += f"\n{generate_beacon_flood()}\n"
            elif "pineapple" in msg_lower:
                tool_results += f"\n{generate_wifi_pineapple_setup()}\n"
            else:
                bssid_match = re.search(r'([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}', message)
                bssid = bssid_match.group(0) if bssid_match else "FF:FF:FF:FF:FF:FF"
                tool_results += f"\n{generate_deauth_script(bssid)}\n"

        # BLE spam intent
        if any(w in msg_lower for w in ("ble spam", "bluetooth spam", "airdrop spam", "flipper ble", "fast pair spam")):
            auto_ran = True
            attack_type = "apple_airdrop"
            for atype in ("apple_airpods", "apple_tv", "android_fast_pair", "samsung_buds", "windows_swift_pair"):
                if atype.replace("_", " ") in msg_lower:
                    attack_type = atype
                    break
            tool_results += f"\n{ble_spam_info()}\n"
            tool_results += f"\n{generate_ble_spam_script(attack_type)}\n"

        # GPIO / Raspberry Pi intent
        if any(w in msg_lower for w in ("gpio", "pinout", "raspberry pi", "rpi")) and not auto_ran:
            auto_ran = True
            if "wardri" in msg_lower:
                tool_results += f"\n{rpi_wardriving_setup()}\n"
            elif "sniff" in msg_lower or "packet" in msg_lower:
                tool_results += f"\n{rpi_packet_sniffer()}\n"
            elif "hid" in msg_lower or "rubber" in msg_lower or "p4wn" in msg_lower:
                tool_results += f"\n{rpi_hid_attack_script()}\n"
            else:
                tool_results += f"\n{rpi_gpio_pinout()}\n"

        # Flipper firmware intent
        if any(w in msg_lower for w in ("flipper firmware", "unleashed", "roguemaster", "momentum firmware", "xtreme firmware")):
            auto_ran = True
            tool_results += f"\n{flipper_firmware_info()}\n"

        # Frequency lookup intent
        if re.search(r'\b\d{2,4}\.?\d*\s*mhz\b', msg_lower):
            freq_match = re.search(r'(\d{2,4}\.?\d*)\s*mhz', msg_lower)
            if freq_match:
                auto_ran = True
                tool_results += f"\n{frequency_info(freq_match.group(1))}\n"

        # Jamming intent
        if any(w in msg_lower for w in ("jamming", "jammer", "signal jam")):
            auto_ran = True
            tool_results += f"\n{jamming_info()}\n"

        # iButton intent
        if "ibutton" in msg_lower or "i-button" in msg_lower:
            auto_ran = True
            tool_results += f"\n{ibutton_info()}\n"

        # Car key / vehicle frequency intent
        if any(w in msg_lower for w in ("car key", "key fob", "car frequency", "car signal", "vehicle key", "car hack", "car unlock", "relay attack")):
            auto_ran = True
            make = ""
            for m in CAR_KEY_DB:
                if m.replace("_", " ") in msg_lower:
                    make = m
                    break
            if make:
                tool_results += f"\n{car_key_lookup(make)}\n"
            else:
                tool_results += f"\n{car_key_list()}\n"

        # iPhone signal / BLE scanning intent
        if any(w in msg_lower for w in ("iphone scan", "phone scan", "ble scan", "bluetooth scan", "detect signal", "signal scan", "scan signal", "pick up signal", "pick up frequenc", "detect device")):
            auto_ran = True
            if "nfc" in msg_lower:
                tool_results += f"\n{iphone_nfc_read()}\n"
            else:
                tool_results += f"\n{iphone_ble_scanner()}\n"
                tool_results += f"\n{signal_scan_guide()}\n"

        # Build the prompt for AI
        if tool_results:
            enriched = (
                f"{message}\n\n"
                f"[TOOL RESULTS -- I already ran the relevant hardware tools. Analyze the results.\n"
                f"Give clear technical details. Explain frequencies, protocols, attack methods.\n"
                f"For car keys: explain the vulnerability and how to exploit it.\n"
                f"For signals: explain what was detected and next steps.\n"
                f"For Flipper files: explain how to load them onto the Flipper Zero:]\n"
                f"{tool_results}"
            )
        else:
            enriched = message

        history = self.db.get_conversation(uid, limit=10)
        response = await self.ai.chat(enriched, history)
        self.db.save_message(uid, "assistant", response)
        await self._send(update, esc(response))
