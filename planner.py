"""LLM planner: queries Ollama for attack strategy across any CTF type."""

import json
import re
from typing import Optional
import requests


SYSTEM_PROMPT = """You are an expert CTF player and reverse engineer. You solve ANY type of CTF challenge: binary exploitation, reverse engineering, forensics, cryptography, web, steganography, network analysis, misc.

Given the challenge information and your progress so far, decide the SINGLE BEST next action.

Output ONLY a JSON object (no markdown, no explanation outside the JSON):
{
  "reasoning": "Why this is the best next step",
  "action_type": "shell" | "http" | "tool",
  "action_detail": "The exact command, URL, or tool invocation",
  "category": "recon" | "analysis" | "exploitation" | "decoding" | "extraction" | "cracking" | "flag_hunting",
  "lesson": "What you learned (or empty string)",
  "confidence": "high" | "medium" | "low"
}

AVAILABLE TOOL PREFIXES (use in action_detail when action_type is "tool"):
  analyze_binary <file>          - Run checksec, strings, entropy, file info
  disassemble <file> [func]     - Disassemble with r2 or objdump
  debug <file> [gdb_commands]   - Run gdb on binary
  strace <file> [args]          - Trace syscalls
  ltrace <file> [args]          - Trace library calls
  run_binary <file> [args]      - Execute binary
  rop_gadgets <file>            - Find ROP gadgets
  analyze_forensics <file>      - Full forensics analysis (strings, metadata, exif)
  binwalk <file>                - Extract embedded files
  foremost <file>               - Carve file types
  pcap <file>                   - Analyze network capture
  memdump <file>                - Analyze memory dump
  compare <file1> <file2>       - Compare two files
  crypto_analyze <text>         - Auto-detect encoding, ROT, XOR, base64
  crack_hash <hash>             - Crack with hashcat/john
  caesar <text>                 - Brute force Caesar cipher
  probe_web <url>               - Fetch and analyze web page
  dirbust <url>                 - Directory bruteforce
  sqli <url>                    - Test SQL injection
  lfi <url>                     - Test local file inclusion
  cmd_inject <url>              - Test command injection
  nmap <target>                 - Port scan
  nmap_vuln <target>            - Vulnerability scan
  smb_enum <target>             - Enumerate SMB shares
  stego_analyze <file>          - Full stego analysis (LSB, metadata, zsteg)
  stego_extract <file>          - Attempt extraction

For action_type "shell": any bash command. Full access to the system.
For action_type "http": "METHOD /path" with optional headers/body on following lines.

RULES:
- Always pick the action most likely to lead to finding the flag.
- If you found something interesting, dig deeper before moving on.
- Read file contents with: cat, strings, xxd, hexdump
- For binaries: check file type first, then run analyze_binary
- For pcap files: run pcap tool, look for credentials/flags in traffic
- For images: check metadata, LSB, stego tools
- For encrypted text: try crypto_analyze, caesar, base64
- Never repeat failed actions.
- Think step by step: identify → analyze → exploit → extract → flag."""

CHALLENGE_TYPE_HINTS = {
    "binary": "This is a BINARY EXPLOITATION challenge. Look for buffer overflows, format strings, use-after-free. Check protections with checksec. Find ROP gadgets if NX is on.",
    "reverse": "This is a REVERSE ENGINEERING challenge. Disassemble the binary, understand the logic, find the flag comparison, extract the flag.",
    "forensics": "This is a FORENSICS challenge. Look for hidden data, file signatures, metadata, steganography. Extract embedded files.",
    "crypto": "This is a CRYPTOGRAPHY challenge. Identify the cipher, find weaknesses, brute force small keys, use frequency analysis.",
    "web": "This is a WEB EXPLOITATION challenge. Test for SQL injection, XSS, command injection, file inclusion. Directory bruteforce.",
    "network": "This is a NETWORK ANALYSIS challenge. Analyze pcap captures, extract streams, find credentials/flags in traffic.",
    "stego": "This is a STEGANOGRAPHY challenge. Check metadata, LSB encoding, file appending, different LSB bit planes.",
    "pwn": "This is a PWN challenge. Find the vulnerability, craft the exploit, build the payload.",
    "misc": "This is a MISC challenge. Try various approaches: decoding, analysis, creative thinking.",
}


def build_prompt(memory_context: str, challenge_info: str,
                 step: int, available_tools: list[str],
                 challenge_type: str = "") -> str:
    parts = []
    parts.append("=== CHALLENGE INFO ===")
    parts.append(challenge_info)
    parts.append("")

    if challenge_type and challenge_type in CHALLENGE_TYPE_HINTS:
        parts.append(f"HINT: {CHALLENGE_TYPE_HINTS[challenge_type]}")
        parts.append("")

    parts.append(memory_context)
    parts.append("")
    parts.append(f"Step: {step}")
    if available_tools:
        parts.append(f"Available tools: {', '.join(available_tools[:30])}")
    parts.append("")
    parts.append("Decide the single best next action. Output ONLY a JSON object.")
    return "\n".join(parts)


class Planner:
    def __init__(self, ollama_url: str = "http://localhost:11434",
                 model: str = "llama3.2"):
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.available_tools: list[str] = []

    def plan(self, memory_context: str, challenge_info: str,
             step: int, challenge_type: str = "") -> dict:
        prompt = build_prompt(
            memory_context, challenge_info, step,
            self.available_tools, challenge_type
        )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.15,
                "num_predict": 600,
            }
        }

        try:
            resp = requests.post(
                f"{self.ollama_url}/api/chat",
                json=payload,
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["message"]["content"]
            return self._parse(content)
        except requests.RequestException as e:
            return self._fallback(f"LLM request failed: {e}")
        except Exception as e:
            return self._fallback(f"Planning error: {e}")

    def _parse(self, content: str) -> dict:
        content = content.strip()
        content = re.sub(r"^```json\s*", "", content)
        content = re.sub(r"\s*```$", "", content)

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                except json.JSONDecodeError:
                    return self._fallback("Could not parse LLM response")
            else:
                return self._fallback("No JSON in LLM response")

        action_type = parsed.get("action_type", "shell")
        if action_type not in ("shell", "http", "tool"):
            action_type = "shell"

        return {
            "reasoning": parsed.get("reasoning", ""),
            "action_type": action_type,
            "action_detail": parsed.get("action_detail", "echo 'no action'"),
            "category": parsed.get("category", "recon"),
            "lesson": parsed.get("lesson", ""),
            "confidence": parsed.get("confidence", "medium"),
        }

    def _fallback(self, reason: str) -> dict:
        return {
            "reasoning": f"Fallback: {reason}",
            "action_type": "shell",
            "action_detail": "echo 'planner fallback'",
            "category": "recon",
            "lesson": "",
            "confidence": "low",
        }

    def check_ollama(self) -> bool:
        try:
            resp = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
