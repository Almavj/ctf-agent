"""Flag parser: detects CTF flags in any output."""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class FoundFlag:
    value: str
    pattern_name: str
    context: str


class FlagParser:
    PATTERNS = {
        "flag_braces": re.compile(r"flag\{[^\}]{3,}\}", re.IGNORECASE),
        "ctf_braces": re.compile(r"CTF\{[^\}]{3,}\}", re.IGNORECASE),
        "htb": re.compile(r"HTB\{[^\}]{3,}\}", re.IGNORECASE),
        "thm": re.compile(r"THM\{[^\}]{3,}\}", re.IGNORECASE),
        "picoctf": re.compile(r"picoCTF\{[^\}]{3,}\}", re.IGNORECASE),
        "hack": re.compile(r"hack\{[^\}]{3,}\}", re.IGNORECASE),
        "flag_eq": re.compile(r"(?:flag|root_flag|user_flag)\s*[:=]\s*([a-zA-Z0-9_\-!@#$%^&*]{8,})", re.IGNORECASE),
        "brackets": re.compile(r"[\[\(]([A-Za-z0-9_\-!@#$%^&*]{16,})[\]\)]"),
        "hex_flag": re.compile(r"(?:0x)?([0-9a-fA-F]{32,64})"),
        "base64_like": re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),
    }

    def __init__(self, extra_patterns: list[str] = None):
        if extra_patterns:
            for i, p in enumerate(extra_patterns):
                try:
                    self.PATTERNS[f"custom_{i}"] = re.compile(p, re.IGNORECASE)
                except re.error:
                    pass

    def extract(self, text: str) -> list[FoundFlag]:
        if not text:
            return []
        found = []
        seen = set()

        for name, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0).strip()
                if value in seen or len(value) < 6:
                    continue
                seen.add(value)
                start = max(0, match.start() - 40)
                end = min(len(text), match.end() + 40)
                context = text[start:end].replace("\n", " ")
                found.append(FoundFlag(
                    value=value, pattern_name=name, context=context
                ))

        found.sort(key=lambda f: len(f.value), reverse=True)
        return found

    def is_flag(self, text: str) -> bool:
        return len(self.extract(text)) > 0

    def best_flag(self, text: str) -> Optional[str]:
        flags = self.extract(text)
        return flags[0].value if flags else None

    def clean(self, flag: str) -> str:
        flag = flag.strip()
        flag = re.sub(r"^\s*[\[\('\"]+", "", flag)
        flag = re.sub(r"[\]\)'\"]+\s*$", "", flag)
        return flag
