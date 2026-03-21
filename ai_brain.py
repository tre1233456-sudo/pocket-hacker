"""
Pocket Hacker - AI Brain
Groq-powered cybersecurity AI with conversation memory.
"""

import json
import logging
import httpx
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AIBrain:
    """Cybersecurity AI brain — Groq-powered."""

    def __init__(self, config):
        self.config = config
        self.system_prompt = config.system_prompt
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(config.ollama_timeout))
        self.backend = "groq" if config.groq_key else "ollama"
        logger.info(f"AI Backend: {self.backend}")

    async def close(self):
        await self._client.aclose()

    async def _generate(self, prompt: str, system: str = None,
                        history: List[Dict] = None, temperature: float = 0.3) -> str:
        if self.backend == "groq":
            return await self._call_groq(prompt, system, history, temperature)
        return await self._call_ollama(prompt, system, history, temperature)

    async def _call_groq(self, prompt: str, system: str = None,
                         history: List[Dict] = None, temperature: float = 0.3) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

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
                    "max_tokens": 4096,
                    "top_p": 0.9,
                }
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            elif r.status_code == 429:
                return "⚠️ Rate limited — wait a moment and try again."
            else:
                logger.error(f"Groq error {r.status_code}: {r.text[:300]}")
                return f"AI error (Groq {r.status_code})"
        except httpx.TimeoutException:
            return "AI timed out. Try a shorter question."
        except Exception as e:
            logger.error(f"Groq error: {e}")
            return f"AI error: {str(e)}"

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
        return await self._generate(message, system=self.system_prompt, history=history)

    async def analyze_target(self, target: str, scan_type: str = "general") -> str:
        prompt = f"""I need to perform authorized security testing on: {target}
Scan type: {scan_type}

Provide a detailed methodology:
1. Reconnaissance commands (passive & active)
2. Enumeration commands
3. Vulnerability assessment approach
4. Suggested tools and exact commands
5. What to look for in the output

Format with clear command blocks and explanations."""
        return await self._generate(prompt, system=self.system_prompt, temperature=0.2)

    async def explain_tool(self, tool_name: str) -> str:
        prompt = f"""Give me a comprehensive cheat sheet for: {tool_name}

Include:
- What it does
- Installation (if needed)
- 10-15 most useful commands/flags with examples
- Common use cases in pentesting
- Pro tips
- Example output interpretation

Be detailed and practical."""
        return await self._generate(prompt, system=self.system_prompt, temperature=0.2)

    async def analyze_hash(self, hash_str: str) -> str:
        prompt = f"""Identify and analyze this hash: {hash_str}

1. What type of hash is this? (MD5, SHA1, SHA256, bcrypt, NTLM, etc.)
2. How can I tell? (length, character set, format)
3. What tools can crack it? (hashcat mode, john format)
4. Example commands to crack it
5. If it's a known/common hash, what might it decode to?"""
        return await self._generate(prompt, system=self.system_prompt, temperature=0.1)

    async def ctf_help(self, challenge: str) -> str:
        prompt = f"""Help me solve this CTF challenge:

{challenge}

Approach:
1. Identify the challenge category (crypto, web, pwn, forensics, misc, reverse)
2. Analyze what we're working with
3. Suggest step-by-step solution approach
4. Provide exact commands/scripts/tools needed
5. Explain the underlying concept"""
        return await self._generate(prompt, system=self.system_prompt, temperature=0.3)

    async def generate_payload(self, target_type: str, details: str) -> str:
        prompt = f"""For authorized penetration testing, I need guidance on testing for vulnerabilities.
Target type: {target_type}
Context: {details}

Provide:
1. Common vulnerability patterns to test for
2. Manual testing methodology
3. Relevant tool commands
4. How to verify if vulnerable
5. Remediation recommendations

This is for authorized security testing and reporting."""
        return await self._generate(prompt, system=self.system_prompt, temperature=0.2)

    async def privesc_help(self, os_type: str, info: str = "") -> str:
        prompt = f"""Privilege escalation methodology for authorized testing on {os_type}.
{f"Current info: {info}" if info else ""}

Provide a complete checklist:
1. Information gathering commands
2. Common misconfigurations to check
3. Exploit suggestions based on common findings
4. Tools to use (linpeas, winpeas, etc.)
5. Exact commands for each check"""
        return await self._generate(prompt, system=self.system_prompt, temperature=0.2)

    async def reverse_shell(self, language: str = "all") -> str:
        prompt = f"""Reverse shell cheat sheet for authorized penetration testing.
{"Language/type: " + language if language != "all" else "All common types."}

Include:
- Bash, Python, PHP, Netcat, PowerShell, Perl, Ruby, Java
- Both bind and reverse shells
- Listener setup commands
- Shell upgrade/stabilization techniques (python pty, stty)
- Encoded versions for WAF bypass"""
        return await self._generate(prompt, system=self.system_prompt, temperature=0.1)
