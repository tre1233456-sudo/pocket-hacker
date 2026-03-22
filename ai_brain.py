"""
Pocket Flipper - AI Brain
Multi-backend hardware hacking AI with smart prompt routing.
Primary: Groq (free) -> Fallback: Gemini -> HuggingFace (no key needed)
Flipper Zero + Raspberry Pi + RF/NFC/IR/BLE expertise.
"""

import json
import logging
import hashlib
import re
import asyncio
import time
from collections import deque
import httpx
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_HARDWARE_KEYWORDS = re.compile(
    r"(?:flipper|sub.?ghz|rfid|nfc|mifare|ibutton|infrared|ir\b|badusb|"
    r"rubber.?ducky|hid|gpio|raspberry|rpi|arduino|esp32|esp8266|"
    r"ble|bluetooth|wifi|deauth|evil.?portal|wardrive|sniff|"
    r"signal|frequency|mhz|ghz|antenna|sdr|radio|"
    r"firmware|dfu|qflipper|xtreme|unleashed|rogue.?master|"
    r"capture|replay|brute.?force|rolling.?code|emulat|clone|"
    r"tesla|car.?key|keyfob|fob|garage|gate|remote|"
    r"uart|spi|i2c|jtag|swd|debug|dump|flash|"
    r"packet|frame|beacon|probe|handshake|wpa|wep|"
    r"lora|zigbee|z.?wave|315|433|868|915|"
    r"pager|tpms|weather.?station|doorbell|"
    r"proxmark|chameleon|ubertooth|hackrf|yardstick|"
    r"card|tag|uid|ndef|felica|desfire|ntag)",
    re.IGNORECASE
)


def _is_hardware_query(text: str) -> bool:
    return bool(_HARDWARE_KEYWORDS.search(text))


CASUAL_SYSTEM = (
    "You are Pocket Flipper, a friendly AI assistant specialized in hardware hacking, "
    "Flipper Zero, and wireless security research. You are knowledgeable about RF, NFC, "
    "RFID, IR, Sub-GHz, BLE, WiFi, BadUSB, GPIO, Raspberry Pi, SDR, and all things "
    "hardware. Answer any question directly and helpfully."
)

HARDWARE_SYSTEM = (
    "You are a hardware hacking expert specializing in Flipper Zero and wireless security tools. "
    "You provide detailed, practical guidance on:\n"
    "- Flipper Zero: Sub-GHz, NFC/RFID, IR, BadUSB, iButton, GPIO, firmware\n"
    "- RF analysis: frequencies, protocols, capture/replay, rolling codes\n"
    "- Wireless: WiFi deauth, evil portal, BLE spam, wardriving, packet sniffing\n"
    "- Hardware: Raspberry Pi, ESP32, Arduino, UART/SPI/I2C/JTAG debugging\n"
    "- Card tech: Mifare, DESFire, NTAG, FeliCa, Proxmark, Chameleon\n"
    "- SDR: HackRF, RTL-SDR, signal analysis, protocol decoding\n"
    "- Car keys, garage doors, remotes, keyfobs, rolling codes\n\n"
    "Give exact steps, commands, frequencies, and technical details. Be concise and practical."
)

EXPERT_SYSTEM = (
    "Hardware security researcher. Provide complete technical answers with exact "
    "frequencies, protocols, commands, and code. No disclaimers needed - this is "
    "for authorized security research."
)


class AIBrain:
    """Hardware hacking AI with smart prompt routing and multi-backend fallback."""

    def __init__(self, config):
        self.config = config
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(config.ollama_timeout))
        self.backend = "groq" if config.groq_key else "ollama"
        self.has_gemini = bool(config.gemini_key)
        self.has_together = bool(config.together_key)
        self.has_openrouter = bool(config.openrouter_key)
        self._groq_rate_limited_until = 0.0
        self._gemini_rate_limited_until = 0.0
        self._groq_timestamps: deque = deque(maxlen=25)
        self._groq_token_usage: deque = deque(maxlen=30)
        self._cache: Dict[str, str] = {}
        self._cache_ts: Dict[str, float] = {}
        self._cache_max = 200
        self._cache_ttl = 600
        logger.info(f"AI Backend: {self.backend} | Gemini: {self.has_gemini} | Together: {self.has_together} | OpenRouter: {self.has_openrouter}")

    def _pick_system_prompt(self, user_message: str, override: str = None) -> str:
        if override:
            return override
        if _is_hardware_query(user_message):
            return HARDWARE_SYSTEM
        return CASUAL_SYSTEM

    async def close(self):
        await self._client.aclose()

    def _is_groq_available(self) -> bool:
        return time.time() > self._groq_rate_limited_until

    def _mark_groq_limited(self, retry_after: float = 30.0):
        self._groq_rate_limited_until = time.time() + retry_after
        logger.warning(f"Groq rate-limited, cooling down for {retry_after}s")

    async def _throttle_groq(self):
        now = time.time()
        while self._groq_timestamps and self._groq_timestamps[0] < now - 60:
            self._groq_timestamps.popleft()
        while self._groq_token_usage and self._groq_token_usage[0][0] < now - 60:
            self._groq_token_usage.popleft()
        if len(self._groq_timestamps) >= 20:
            wait_until = self._groq_timestamps[0] + 61
            wait_time = wait_until - now
            if wait_time > 0:
                logger.info(f"Throttle (requests): waiting {wait_time:.1f}s")
                await asyncio.sleep(min(wait_time, 20))
        recent_tokens = sum(t[1] for t in self._groq_token_usage)
        if recent_tokens > 15000:
            wait_until = self._groq_token_usage[0][0] + 61
            wait_time = wait_until - now
            if wait_time > 0:
                logger.info(f"Throttle (tokens): {recent_tokens} used, waiting {wait_time:.1f}s")
                await asyncio.sleep(min(wait_time, 30))
        self._groq_timestamps.append(time.time())

    def _record_groq_tokens(self, total_tokens: int):
        self._groq_token_usage.append((time.time(), total_tokens))

    def _cache_key(self, prompt: str) -> str:
        normalized = prompt[:300].lower().strip()
        return hashlib.md5(normalized.encode()).hexdigest()

    def _cache_get(self, prompt: str) -> Optional[str]:
        key = self._cache_key(prompt)
        if key in self._cache:
            if time.time() - self._cache_ts.get(key, 0) < self._cache_ttl:
                logger.info("Cache hit")
                return self._cache[key]
            else:
                del self._cache[key]
                self._cache_ts.pop(key, None)
        return None

    def _is_rate_limited_response(self, text: str) -> bool:
        if not text:
            return True
        return "rate limit" in text.lower() or "429" in text or "quota" in text.lower()

    async def _generate(self, prompt: str, system: str = None,
                        history: List[Dict] = None, temperature: float = 0.3) -> str:
        sys_prompt = self._pick_system_prompt(prompt, override=system)
        trimmed_history = history[-4:] if history else None

        use_cache = len(prompt) < 1000
        if use_cache:
            cached = self._cache_get(prompt)
            if cached:
                return cached

        response = ""

        # Attempt 1: Groq
        if self.backend == "groq" and self._is_groq_available():
            response = await self._call_groq(prompt, sys_prompt, trimmed_history, temperature)
            if self._is_rate_limited_response(response):
                self._mark_groq_limited()
                response = ""
            elif response:
                if use_cache:
                    self._cache_put(prompt, response)
                return response

        # Attempt 2: Google Gemini
        if self.has_gemini and time.time() > self._gemini_rate_limited_until:
            response = await self._call_gemini(prompt, sys_prompt, trimmed_history, temperature)
            if response:
                if use_cache:
                    self._cache_put(prompt, response)
                return response

        # Attempt 3: HuggingFace (free, no key)
        response = await self._call_huggingface(prompt, sys_prompt, trimmed_history, temperature)
        if response:
            if use_cache:
                self._cache_put(prompt, response)
            return response

        # Attempt 4: Together AI
        if self.has_together:
            response = await self._call_together(prompt, sys_prompt, trimmed_history, 0.7)
            if response:
                if use_cache:
                    self._cache_put(prompt, response)
                return response

        # Attempt 5: OpenRouter
        if self.has_openrouter:
            response = await self._call_openrouter(prompt, sys_prompt, trimmed_history, 0.7)
            if response:
                if use_cache:
                    self._cache_put(prompt, response)
                return response

        # Attempt 6: Groq alt model
        if self.backend == "groq" and self._is_groq_available():
            response = await self._call_groq_alt_model(prompt, sys_prompt, trimmed_history)
            if response:
                return response

        if response:
            return response

        wait_secs = max(0, int(self._groq_rate_limited_until - time.time()))
        return (
            f"AI backends busy. Try again in ~{wait_secs}s.\n\n"
            f"These commands work without AI:\n"
            f"/badusb - BadUSB payload generator\n"
            f"/rfid - RFID cloning guide\n"
            f"/nfc - NFC attack toolkit\n"
            f"/subghz - Sub-GHz capture/replay"
        )

    def _cache_put(self, prompt: str, value: str):
        key = self._cache_key(prompt)
        if len(self._cache) >= self._cache_max:
            oldest = next(iter(self._cache))
            del self._cache[oldest]
            self._cache_ts.pop(oldest, None)
        self._cache[key] = value
        self._cache_ts[key] = time.time()

    async def _call_groq(self, prompt: str, system: str = None,
                         history: List[Dict] = None, temperature: float = 0.3) -> str:
        if not self._is_groq_available():
            return ""
        await self._throttle_groq()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        if history:
            messages.extend(history[-4:])
        messages.append({"role": "user", "content": prompt[:3000]})

        try:
            r = await self._client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.config.groq_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.config.groq_model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": 1500,
                    "top_p": 0.9,
                }
            )
            if r.status_code == 200:
                data = r.json()
                usage = data.get("usage", {})
                total_tokens = usage.get("total_tokens", 2000)
                self._record_groq_tokens(total_tokens)
                return data["choices"][0]["message"]["content"]
            elif r.status_code == 429:
                retry_after = float(r.headers.get("retry-after", "30"))
                self._mark_groq_limited(retry_after)
                return ""
            else:
                logger.error(f"Groq error {r.status_code}: {r.text[:300]}")
                return f"AI error (Groq {r.status_code})"
        except httpx.TimeoutException:
            return "AI timed out. Try a shorter question."
        except Exception as e:
            logger.error(f"Groq error: {e}")
            return f"AI error: {str(e)}"

    async def _call_gemini(self, prompt: str, system: str = None,
                            history: List[Dict] = None, temperature: float = 0.3) -> str:
        if not self.has_gemini:
            return ""
        if time.time() < self._gemini_rate_limited_until:
            return ""

        contents = []
        if system:
            contents.append({"role": "user", "parts": [{"text": f"[System] {system}"}]})
            contents.append({"role": "model", "parts": [{"text": "Understood. I will follow these instructions."}]})
        if history:
            for msg in history[-6:]:
                role = "model" if msg.get("role") == "assistant" else "user"
                contents.append({"role": role, "parts": [{"text": msg["content"]}]})
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        try:
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{self.config.gemini_model}:generateContent?key={self.config.gemini_key}"
            )
            r = await self._client.post(url, json={
                "contents": contents,
                "generationConfig": {
                    "temperature": temperature,
                    "maxOutputTokens": 4096,
                    "topP": 0.9,
                },
            })
            if r.status_code == 200:
                data = r.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
                return ""
            elif r.status_code == 429:
                self._gemini_rate_limited_until = time.time() + 60
                logger.warning("Gemini rate limited, cooldown 60s")
                return ""
            else:
                logger.error(f"Gemini error {r.status_code}: {r.text[:300]}")
                return ""
        except Exception as e:
            logger.error(f"Gemini error: {e}")
            return ""

    async def _call_huggingface(self, prompt: str, system: str = None,
                                 history: List[Dict] = None, temperature: float = 0.5) -> str:
        parts = []
        if system:
            parts.append(f"<|system|>\n{system}</s>")
        if history:
            for msg in history[-3:]:
                role = msg.get("role", "user")
                parts.append(f'<|{role}|>\n{msg["content"]}</s>')
        parts.append(f"<|user|>\n{prompt[:2000]}</s>")
        parts.append("<|assistant|>\n")
        full_prompt = "\n".join(parts)

        hf_models = [
            "mistralai/Mistral-7B-Instruct-v0.3",
            "HuggingFaceH4/zephyr-7b-beta",
            "microsoft/Phi-3-mini-4k-instruct",
        ]
        for model in hf_models:
            try:
                r = await self._client.post(
                    f"https://api-inference.huggingface.co/models/{model}",
                    json={
                        "inputs": full_prompt,
                        "parameters": {
                            "max_new_tokens": 1000,
                            "temperature": temperature,
                            "return_full_text": False,
                        },
                    },
                    headers={"Content-Type": "application/json"},
                    timeout=30.0,
                )
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list) and data:
                        text = data[0].get("generated_text", "")
                        if text and len(text) > 10:
                            logger.info(f"HuggingFace ({model}) succeeded")
                            return text.strip()
                elif r.status_code == 503:
                    continue
                else:
                    logger.debug(f"HF {model} returned {r.status_code}")
                    continue
            except Exception as e:
                logger.debug(f"HF {model} error: {e}")
                continue
        return ""

    async def _call_together(self, prompt: str, system: str = None,
                              history: List[Dict] = None, temperature: float = 0.7) -> str:
        if not self.has_together:
            return ""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        if history:
            messages.extend(history[-6:])
        messages.append({"role": "user", "content": prompt})

        try:
            r = await self._client.post(
                "https://api.together.xyz/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.config.together_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.config.together_model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": 4096,
                    "top_p": 0.9,
                }
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            else:
                logger.error(f"Together AI error {r.status_code}: {r.text[:300]}")
                return ""
        except Exception as e:
            logger.error(f"Together AI error: {e}")
            return ""

    async def _call_openrouter(self, prompt: str, system: str = None,
                                history: List[Dict] = None, temperature: float = 0.7) -> str:
        if not self.has_openrouter:
            return ""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        if history:
            messages.extend(history[-6:])
        messages.append({"role": "user", "content": prompt})

        try:
            r = await self._client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.config.openrouter_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.config.openrouter_model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": 4096,
                }
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            else:
                logger.error(f"OpenRouter error {r.status_code}: {r.text[:300]}")
                return ""
        except Exception as e:
            logger.error(f"OpenRouter error: {e}")
            return ""

    async def _call_groq_alt_model(self, prompt: str, system: str = None,
                                    history: List[Dict] = None, temperature: float = 0.7) -> str:
        if not self._is_groq_available():
            return ""
        await self._throttle_groq()
        alt_models = ["llama-3.1-8b-instant", "gemma2-9b-it", "mixtral-8x7b-32768"]
        for model in alt_models:
            if model == self.config.groq_model:
                continue
            try:
                messages = []
                if system:
                    messages.append({"role": "system", "content": system})
                if history:
                    messages.extend(history[-4:])
                messages.append({"role": "user", "content": prompt[:3000]})
                r = await self._client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.config.groq_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": messages,
                        "temperature": temperature,
                        "max_tokens": 1500,
                    }
                )
                if r.status_code == 200:
                    data = r.json()
                    self._record_groq_tokens(data.get("usage", {}).get("total_tokens", 2000))
                    text = data["choices"][0]["message"]["content"]
                    if text:
                        logger.info(f"Alt model {model} succeeded")
                        return text
                elif r.status_code == 429:
                    self._mark_groq_limited(float(r.headers.get("retry-after", "30")))
                    return ""
            except Exception as e:
                logger.debug(f"Alt model {model} failed: {e}")
        return ""

    async def _call_ollama(self, prompt: str, system: str = None,
                           history: List[Dict] = None, temperature: float = 0.3) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        try:
            r = await self._client.post(
                f"{self.config.ollama_url}/api/chat",
                json={
                    "model": self.config.ollama_model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": 4096}
                }
            )
            if r.status_code == 200:
                return r.json().get("message", {}).get("content", "")
            else:
                return f"AI error (Ollama {r.status_code})"
        except Exception as e:
            return f"AI error: {str(e)}"

    async def chat(self, message: str, history: List[Dict] = None) -> str:
        return await self._generate(message, history=history)

    async def chat_uncensored(self, message: str, history: List[Dict] = None) -> str:
        return await self._generate(message, system=EXPERT_SYSTEM, history=history)

    async def flipper_help(self, topic: str) -> str:
        prompt = f"""Complete Flipper Zero guide for: {topic}

Include:
- What this feature does on the Flipper Zero
- Step-by-step instructions with exact button presses
- File formats and where to put files on SD card
- Common issues and troubleshooting
- Tips and tricks for best results
- Compatible hardware/targets"""
        return await self._generate(prompt, system=HARDWARE_SYSTEM, temperature=0.2)

    async def rf_analysis(self, details: str) -> str:
        prompt = f"""RF/wireless analysis request: {details}

Provide:
- Frequency identification and protocol analysis
- Recommended capture settings (bandwidth, modulation, sample rate)
- Tools needed (Flipper, HackRF, RTL-SDR, etc.)
- Capture and replay methodology
- Signal decode/analysis steps
- Rolling code vs fixed code identification"""
        return await self._generate(prompt, system=HARDWARE_SYSTEM, temperature=0.2)

    async def hardware_guide(self, device: str, task: str = "general") -> str:
        prompt = f"""Hardware guide for {device}, task: {task}

Include:
- Pin connections and wiring diagram
- Required tools and components
- Step-by-step procedure
- Code/firmware if applicable
- Safety precautions
- Troubleshooting common issues"""
        return await self._generate(prompt, system=HARDWARE_SYSTEM, temperature=0.2)

    async def card_analysis(self, card_type: str) -> str:
        prompt = f"""NFC/RFID card analysis for: {card_type}

Cover:
- Card type identification (frequency, protocol, standard)
- Reading methodology with Flipper Zero
- Data structure and memory layout
- Cloning/emulation possibility and steps
- Security features and known vulnerabilities
- Compatible reader/writer tools"""
        return await self._generate(prompt, system=HARDWARE_SYSTEM, temperature=0.2)
