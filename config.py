"""Configuration for Pocket Flipper."""
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Config:
    telegram_token: str = ""
    authorized_users: List[int] = field(default_factory=list)
    groq_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"
    gemini_key: str = ""
    gemini_model: str = "gemini-2.0-flash"
    together_key: str = ""
    together_model: str = "cognitivecomputations/dolphin-2.5-mixtral-8x7b"
    openrouter_key: str = ""
    openrouter_model: str = "cognitivecomputations/dolphin3.0-r1-mistral-24b:free"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ollama_timeout: float = 120.0

    system_prompt: str = "You are Pocket Flipper, an AI assistant specialized in Flipper Zero, hardware hacking, RF/NFC/IR/BLE, and wireless security research. Help the user with any question."

    @classmethod
    def from_env(cls) -> "Config":
        users_str = os.getenv("AUTHORIZED_USERS", "")
        users = [int(u.strip()) for u in users_str.split(",") if u.strip().isdigit()]
        return cls(
            telegram_token=os.getenv("TELEGRAM_TOKEN", ""),
            authorized_users=users,
            groq_key=os.getenv("GROQ_API_KEY", ""),
            groq_model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
            gemini_key=os.getenv("GEMINI_API_KEY", ""),
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
            together_key=os.getenv("TOGETHER_API_KEY", ""),
            together_model=os.getenv("TOGETHER_MODEL", "cognitivecomputations/dolphin-2.5-mixtral-8x7b"),
            openrouter_key=os.getenv("OPENROUTER_API_KEY", ""),
            openrouter_model=os.getenv("OPENROUTER_MODEL", "cognitivecomputations/dolphin3.0-r1-mistral-24b:free"),
            ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
            ollama_model=os.getenv("OLLAMA_MODEL", "llama3"),
            ollama_timeout=float(os.getenv("OLLAMA_TIMEOUT", "120")),
        )
