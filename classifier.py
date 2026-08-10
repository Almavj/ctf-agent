"""Challenge classifier: determines what type of CTF challenge the input is."""

import magic
import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ChallengeType(Enum):
    BINARY = "binary"
    FORENSICS = "forensics"
    CRYPTO = "crypto"
    WEB = "web"
    NETWORK = "network"
    STEGO = "stego"
    REVERSE = "reverse"
    PWN = "pwn"
    MISC = "misc"
    UNKNOWN = "unknown"


@dataclass
class Classification:
    challenge_type: ChallengeType
    confidence: float
    file_type: str = ""
    mime_type: str = ""
    details: dict = field(default_factory=dict)
    raw_info: str = ""

    def summary(self) -> str:
        lines = [
            f"Type: {self.challenge_type.value}",
            f"Confidence: {self.confidence:.0%}",
            f"File type: {self.file_type}",
            f"MIME: {self.mime_type}",
        ]
        for k, v in self.details.items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)


BINARY_MAGIC = [
    ELF_MAGIC := b"\x7fELF",
    PE_MAGIC := b"MZ",
    MachO_MAGIC := b"\xfe\xed\xfa",
]

ARCHIVE_MAGIC = [b"PK", b"Rar!", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b"]

CRYPTO_INDICATORS = [
    "encrypted", "cipher", "hash", "md5", "sha", "base64",
    "rot13", "xor", "aes", "des", "rsa", "pgp", "gpg",
    "crack", "decrypt", "encode", "decode",
]

FORENSICS_EXTENSIONS = [
    ".pcap", ".pcapng", ".raw", ".mem", ".dump", ".dd", ".img",
    ".iso", ".elf", ".core", ".vmem", ".vmsn", ".hprof",
]

STEGO_EXTENSIONS = [
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".wav", ".mp3",
    ".pdf", ".docx",
]

WEB_INDICATORS = [
    "http://", "https://", "html", "php", "js", "cookie",
    "login", "admin", "api", "endpoint",
]


class Classifier:
    def __init__(self):
        self._magic = magic.Magic(mime=True)
        self._magic_type = magic.Magic()

    def classify_input(self, user_input: str) -> Classification:
        user_input = user_input.strip()

        if self._is_url(user_input):
            return Classification(
                challenge_type=ChallengeType.WEB,
                confidence=0.9,
                file_type="URL",
                details={"url": user_input},
            )

        if self._is_ip(user_input):
            return Classification(
                challenge_type=ChallengeType.WEB,
                confidence=0.7,
                file_type="IP address",
                details={"ip": user_input},
            )

        if os.path.isfile(user_input):
            return self._classify_file(user_input)

        if os.path.isdir(user_input):
            return self._classify_directory(user_input)

        return self._classify_text(user_input)

    def _classify_file(self, filepath: str) -> Classification:
        info = Classification(
            challenge_type=ChallengeType.UNKNOWN,
            confidence=0.5,
        )

        try:
            info.mime_type = self._magic.from_file(filepath)
        except Exception:
            pass
        try:
            info.file_type = self._magic_type.from_file(filepath)
        except Exception:
            pass

        ext = os.path.splitext(filepath)[1].lower()
        size = os.path.getsize(filepath)
        info.details["path"] = os.path.abspath(filepath)
        info.details["size"] = f"{size:,} bytes"
        info.details["extension"] = ext

        try:
            result = subprocess.run(
                ["file", filepath], capture_output=True, text=True, timeout=5
            )
            info.details["file_analysis"] = result.stdout.strip()
            info.raw_info = result.stdout
        except Exception:
            pass

        if ext in [".elf", ""] and "ELF" in info.file_type.upper():
            info.challenge_type = ChallengeType.BINARY
            info.confidence = 0.85
            if "dynamically linked" in info.file_type.lower():
                info.details["linking"] = "dynamic"
            if "stripped" in info.file_type.lower():
                info.details["stripped"] = "yes"
            elif "not stripped" in info.file_type.lower():
                info.details["stripped"] = "no"

        elif ext in [".exe", ".dll", ".msi"] or "PE32" in info.file_type:
            info.challenge_type = ChallengeType.BINARY
            info.confidence = 0.85

        elif ext in FORENSICS_EXTENSIONS or "pcap" in info.file_type.lower():
            info.challenge_type = ChallengeType.FORENSICS
            info.confidence = 0.8

        elif ext in [".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz"]:
            info.challenge_type = ChallengeType.FORENSICS
            info.confidence = 0.7
            info.details["archive"] = "yes"

        elif ext in STEGO_EXTENSIONS:
            info.challenge_type = ChallengeType.STEGO
            info.confidence = 0.75
            if ext in [".png", ".jpg", ".jpeg", ".gif", ".bmp"]:
                info.details["image"] = "yes"
            elif ext in [".wav", ".mp3"]:
                info.details["audio"] = "yes"

        elif ext in [".py", ".rb", ".js", ".php", ".sh"]:
            info.challenge_type = ChallengeType.CRYPTO
            info.confidence = 0.6
            info.details["script"] = "yes"

        elif ext == ".enc" or ext == ".encrypted":
            info.challenge_type = ChallengeType.CRYPTO
            info.confidence = 0.8

        elif ext in [".txt", ".md", ".log", ".csv", ".json", ".xml"]:
            content = self._read_head(filepath)
            for indicator in CRYPTO_INDICATORS:
                if indicator in content.lower():
                    info.challenge_type = ChallengeType.CRYPTO
                    info.confidence = 0.7
                    break
            if info.challenge_type == ChallengeType.UNKNOWN:
                info.challenge_type = ChallengeType.MISC
                info.confidence = 0.6

        elif ext in [".pdf", ".docx", ".pptx"]:
            info.challenge_type = ChallengeType.FORENSICS
            info.confidence = 0.65

        else:
            content = self._read_head(filepath)
            if self._looks_like_binary(content.encode("latin-1", errors="replace")):
                if "ELF" in info.file_type or "executable" in info.file_type.lower():
                    info.challenge_type = ChallengeType.BINARY
                    info.confidence = 0.8
                else:
                    info.challenge_type = ChallengeType.FORENSICS
                    info.confidence = 0.6
            else:
                for indicator in CRYPTO_INDICATORS:
                    if indicator in content.lower():
                        info.challenge_type = ChallengeType.CRYPTO
                        info.confidence = 0.7
                        break
                if info.challenge_type == ChallengeType.UNKNOWN:
                    info.challenge_type = ChallengeType.MISC
                    info.confidence = 0.5

        return info

    def _classify_directory(self, dirpath: str) -> Classification:
        files = []
        for root, dirs, filenames in os.walk(dirpath):
            for fn in filenames:
                files.append(os.path.join(root, fn))

        info = Classification(
            challenge_type=ChallengeType.UNKNOWN,
            confidence=0.5,
            file_type="Directory",
        )
        info.details["path"] = dirpath
        info.details["file_count"] = str(len(files))

        extensions = [os.path.splitext(f)[1].lower() for f in files]
        ext_set = set(extensions)

        if any(ext in ext_set for ext in [".pcap", ".pcapng"]):
            info.challenge_type = ChallengeType.NETWORK
            info.confidence = 0.85
        elif any(ext in ext_set for ext in [".py", ".js", ".php", ".html"]):
            info.challenge_type = ChallengeType.WEB
            info.confidence = 0.7
        elif any(ext in ext_set for ext in [".png", ".jpg", ".wav"]):
            info.challenge_type = ChallengeType.STEGO
            info.confidence = 0.7
        else:
            info.challenge_type = ChallengeType.MISC
            info.confidence = 0.5

        return info

    def _classify_text(self, text: str) -> Classification:
        text_lower = text.lower().strip()

        if any(ind in text_lower for ind in WEB_INDICATORS):
            return Classification(
                challenge_type=ChallengeType.WEB,
                confidence=0.75,
                file_type="Text (URL/HTML)",
                details={"content_preview": text[:200]},
            )

        for indicator in CRYPTO_INDICATORS:
            if indicator in text_lower:
                return Classification(
                    challenge_type=ChallengeType.CRYPTO,
                    confidence=0.7,
                    file_type="Text (crypto-related)",
                    details={"content_preview": text[:200]},
                )

        if re.search(r"^[A-Za-z0-9+/=]{20,}$", text.strip()):
            return Classification(
                challenge_type=ChallengeType.CRYPTO,
                confidence=0.6,
                file_type="Text (possible base64)",
                details={"content_preview": text[:200]},
            )

        if re.search(r"\\x[0-9a-fA-F]{2}", text):
            return Classification(
                challenge_type=ChallengeType.BINARY,
                confidence=0.6,
                file_type="Text (hex-encoded)",
                details={"content_preview": text[:200]},
            )

        return Classification(
            challenge_type=ChallengeType.MISC,
            confidence=0.4,
            file_type="Text",
            details={"content_preview": text[:200]},
        )

    def _is_url(self, s: str) -> bool:
        return bool(re.match(r"https?://", s, re.IGNORECASE))

    def _is_ip(self, s: str) -> bool:
        return bool(re.match(
            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", s
        ))

    def _read_head(self, filepath: str, n: int = 2048) -> str:
        try:
            with open(filepath, "r", errors="replace") as f:
                return f.read(n)
        except Exception:
            return ""

    def _looks_like_binary(self, data: bytes) -> bool:
        if len(data) < 16:
            return False
        null_count = data[:1024].count(b"\x00")
        return null_count > len(data[:1024]) * 0.1
