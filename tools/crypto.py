"""Cryptography tools: hash cracking, encoding, decryption."""

import base64
import binascii
from typing import Optional
from .system import SystemTools, ToolResult


class CryptoTools:
    def __init__(self, sys_tools: SystemTools):
        self.sys = sys_tools

    def analyze_text(self, text: str) -> ToolResult:
        results = []
        text = text.strip()

        try:
            b64decoded = base64.b64decode(text)
            results.append(f"Base64 decoded (bytes): {b64decoded[:500]}")
            try:
                results.append(f"Base64 decoded (utf-8): {b64decoded.decode('utf-8')}")
            except UnicodeDecodeError:
                pass
        except Exception:
            pass

        try:
            hex_decoded = binascii.unhexlify(text.replace(" ", ""))
            results.append(f"Hex decoded: {hex_decoded[:500]}")
        except Exception:
            pass

        rotated = []
        for shift in range(1, 26):
            decoded = ""
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    decoded += chr((ord(c) - base + shift) % 26 + base)
                else:
                    decoded += c
            if "flag" in decoded.lower() or "ctf" in decoded.lower():
                rotated.append(f"ROT{shift}: {decoded}")
        if rotated:
            results.append("ROT CIPHER HITS:\n" + "\n".join(rotated))

        xor_results = self._try_common_xor(text)
        if xor_results:
            results.append("XOR ATTEMPTS:\n" + "\n".join(xor_results))

        return ToolResult(
            tool="crypto_analyze", success=True,
            output="\n\n".join(results) or "No automatic analysis results",
            command="crypto_analyze"
        )

    def _try_common_xor(self, text: str) -> list[str]:
        results = []
        try:
            data = bytes.fromhex(text) if all(
                c in "0123456789abcdefABCDEF" for c in text
            ) else text.encode()
        except ValueError:
            data = text.encode()

        for key in range(1, 256):
            decoded = bytes([b ^ key for b in data])
            try:
                s = decoded.decode("utf-8", errors="strict")
                if "flag" in s.lower() or "ctf" in s.lower():
                    results.append(f"XOR key {key} (0x{key:02x}): {s[:200]}")
            except Exception:
                pass
            if len(results) >= 5:
                break
        return results

    def crack_hash(self, hash_value: str, hash_type: str = "") -> ToolResult:
        if not hash_type:
            hash_type = self._detect_hash_type(hash_value)

        if self.sys.available("hashcat"):
            mode = self._hashcat_mode(hash_type)
            if mode:
                cmd = (f"hashcat -m {mode} '{hash_value}' "
                       f"/usr/share/wordlists/rockyou.txt 2>/dev/null | head -5")
                result = self.sys.run(cmd, timeout=120)
                if result.success and result.output.strip():
                    return result

        if self.sys.available("john"):
            tmp = f"/tmp/_ctf_hash_{hash_value[:8]}"
            with open(tmp, "w") as f:
                f.write(hash_value + "\n")
            cmd = f"john '{tmp}' --wordlist=/usr/share/wordlists/rockyou.txt 2>/dev/null"
            result = self.sys.run(cmd, timeout=120)
            show = self.sys.run(f"john --show '{tmp}' 2>/dev/null")
            if show.success and show.output.strip():
                return ToolResult(
                    tool="john", success=True, output=show.output,
                    command=f"john {hash_value}"
                )

        return ToolResult(
            tool="hash_crack", success=False, output="",
            error=f"Could not crack {hash_type} hash (need hashcat or john with wordlist)"
        )

    def rsa_decrypt(self, n: str, e: str, c: str) -> ToolResult:
        script = f"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import gmpy2

n = int('{n}')
e = int('{e}')
c = int('{c}')

# Try factoring with gmpy2
for i in range(2, 1000000):
    if n % i == 0:
        p = i
        q = n // i
        phi = (p - 1) * (q - 1)
        d = int(gmpy2.invert(e, phi))
        m = pow(c, d, n)
        print(f'p={{p}}, q={{q}}')
        print(f'd={{d}}')
        print(f'message={{m}}')
        print(f'text=\\'{{bytes.fromhex(hex(m)[2:])}}\\'')
        break
"""
        return self.sys.run(f"python3 -c '''{script}'''", timeout=30)

    def vigenere_decrypt(self, ciphertext: str, key: str) -> ToolResult:
        result = []
        plaintext = ""
        key_idx = 0
        for c in ciphertext:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[key_idx % len(key)].lower()) - ord('a')
                plaintext += chr((ord(c) - base - shift) % 26 + base)
                key_idx += 1
            else:
                plaintext += c
        result.append(f"Key: {key}")
        result.append(f"Plaintext: {plaintext}")
        return ToolResult(
            tool="vigenere", success=True,
            output="\n".join(result),
            command=f"vigenere_decrypt"
        )

    def caesar_brute(self, text: str) -> ToolResult:
        results = []
        for shift in range(26):
            decoded = ""
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    decoded += chr((ord(c) - base - shift) % 26 + base)
                else:
                    decoded += c
            results.append(f"Shift {shift:2d}: {decoded}")
        return ToolResult(
            tool="caesar", success=True,
            output="\n".join(results),
            command="caesar_brute"
        )

    def _detect_hash_type(self, h: str) -> str:
        h = h.strip()
        if len(h) == 32:
            return "md5"
        elif len(h) == 40:
            return "sha1"
        elif len(h) == 64:
            return "sha256"
        elif len(h) == 128:
            return "sha512"
        elif h.startswith("$2"):
            return "bcrypt"
        elif h.startswith("$6"):
            return "sha512crypt"
        elif h.startswith("$5"):
            return "sha256crypt"
        elif h.startswith("$1"):
            return "md5crypt"
        return "unknown"

    def _hashcat_mode(self, hash_type: str) -> Optional[int]:
        modes = {
            "md5": 0, "sha1": 100, "sha256": 1400,
            "sha512": 1800, "md5crypt": 500,
            "sha256crypt": 7400, "sha512crypt": 1800,
            "bcrypt": 3200,
        }
        return modes.get(hash_type)
