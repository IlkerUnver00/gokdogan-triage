"""Family config extraction (pluggable).

Beyond raw IOC strings, some malware carries *structured* configuration an
analyst wants pulled out verbatim: a Discord webhook a stealer exfils to, a
Telegram bot token, the URL a loader fetches its next stage from. This is a
small registry of extractors — each recognizes one pattern and returns
typed ``ConfigField`` records. Extractors run over the plaintext image and
over strings recovered from XOR/base64 encoding, so a config hidden behind
a single-byte key is still caught. Adding a family is one function plus one
line in ``REGISTRY``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from .models import ConfigField

# --- individual extractors ---------------------------------------------

_DISCORD = re.compile(
    r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", re.I)
_TELEGRAM = re.compile(r"\bbot(\d{6,12}:[A-Za-z0-9_-]{30,45})\b")
_REMOTE_HOSTS = re.compile(
    r"https?://(?:pastebin\.com/raw/|raw\.githubusercontent\.com/|"
    r"gist\.githubusercontent\.com/|transfer\.sh/|paste\.ee/r/|"
    r"cdn\.discordapp\.com/attachments/)[^\s\"'<>]+", re.I)


def _discord(texts: Iterable[str]) -> list[ConfigField]:
    out = []
    for text in texts:
        for m in _DISCORD.finditer(text):
            out.append(ConfigField("Discord webhook", "webhook", m.group(0)))
    return out


def _telegram(texts: Iterable[str]) -> list[ConfigField]:
    out = []
    for text in texts:
        for m in _TELEGRAM.finditer(text):
            out.append(ConfigField("Telegram bot", "bot_token", m.group(1)))
    return out


def _remote_config(texts: Iterable[str]) -> list[ConfigField]:
    out = []
    for text in texts:
        for m in _REMOTE_HOSTS.finditer(text):
            out.append(ConfigField("Remote config / stager", "url", m.group(0)))
    return out


REGISTRY: list[Callable[[Iterable[str]], list[ConfigField]]] = [
    _discord, _telegram, _remote_config,
]


def extract_config(data: bytes, extra_texts: list[str] | None = None) -> list[ConfigField]:
    """Run every extractor over the image and any decoded strings."""
    corpus = [data.decode("latin-1", errors="replace")]
    if extra_texts:
        corpus.extend(extra_texts)

    seen: set[tuple[str, str, str]] = set()
    result: list[ConfigField] = []
    for extractor in REGISTRY:
        for field in extractor(corpus):
            key = (field.family, field.key, field.value)
            if key not in seen:
                seen.add(key)
                result.append(field)
    return result
