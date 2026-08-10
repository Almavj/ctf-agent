"""Executor: unified command execution with full local access."""

import os
import json
import subprocess
from dataclasses import dataclass
from typing import Optional

from tools.system import SystemTools, ToolResult
from tools.binary import BinaryTools
from tools.forensics import ForensicsTools
from tools.crypto import CryptoTools
from tools.web import WebTools
from tools.network import NetworkTools
from tools.stego import StegoTools


class Executor:
    def __init__(self, timeout: int = 60):
        self.sys = SystemTools(timeout=timeout)
        self.binary = BinaryTools(self.sys)
        self.forensics = ForensicsTools(self.sys)
        self.crypto = CryptoTools(self.sys)
        self.web = WebTools(self.sys)
        self.network = NetworkTools(self.sys)
        self.stego = StegoTools(self.sys)

    def execute(self, action_type: str, action_detail: str) -> ToolResult:
        if action_type == "shell":
            return self.sys.run(action_detail)
        elif action_type == "http":
            return self._exec_http(action_detail)
        elif action_type == "tool":
            return self._exec_tool(action_detail)
        else:
            return self.sys.run(action_detail)

    def _exec_http(self, detail: str) -> ToolResult:
        lines = detail.strip().split("\n")
        first = lines[0].strip().split()
        method = first[0] if first else "GET"
        url = first[1] if len(first) > 1 else "/"

        headers = {}
        body = None
        in_headers = True
        body_lines = []

        for line in lines[1:]:
            line = line.strip()
            if in_headers and not line:
                in_headers = False
                continue
            if in_headers and ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
            elif not in_headers:
                body_lines.append(line)

        if body_lines:
            body = "\n".join(body_lines)

        return self.sys.curl(url, method=method, data=body,
                            headers=headers or None)

    def _exec_tool(self, detail: str) -> ToolResult:
        parts = detail.strip().split(None, 1)
        tool_name = parts[0] if parts else ""
        args = parts[1] if len(parts) > 1 else ""

        tool_map = {
            "analyze_binary": lambda a: self.binary.analyze(a),
            "disassemble": lambda a: self.binary.disassemble(a),
            "debug": lambda a: self.binary.debug(a),
            "strace": lambda a: self.binary.strace(a),
            "ltrace": lambda a: self.binary.ltrace(a),
            "run_binary": lambda a: self.binary.run_with_args(a),
            "rop_gadgets": lambda a: self.binary.find_rop_gadgets(a),
            "analyze_forensics": lambda a: self.forensics.full_analysis(a),
            "binwalk": lambda a: self.forensics.binwalk_extract(a, "/tmp/_ctf_binwalk"),
            "foremost": lambda a: self.forensics.foremost_extract(a, "/tmp/_ctf_foremost"),
            "pcap": lambda a: self.forensics.analyze_pcap(a),
            "memdump": lambda a: self.forensics.memory_dump_analysis(a),
            "compare": lambda a: self._exec_compare(a),
            "crypto_analyze": lambda a: self.crypto.analyze_text(a),
            "crack_hash": lambda a: self.crypto.crack_hash(a),
            "caesar": lambda a: self.crypto.caesar_brute(a),
            "probe_web": lambda a: self.web.probe(a),
            "dirbust": lambda a: self.web.directory_bruteforce(a),
            "sqli": lambda a: self.web.sql_injection_test(a),
            "lfi": lambda a: self.web.lfi_test(a),
            "cmd_inject": lambda a: self.web.command_injection_test(a),
            "nikto": lambda a: self.web.nikto_scan(a),
            "whatweb": lambda a: self.web.whatweb_scan(a),
            "nmap": lambda a: self.network.quick_scan(a),
            "nmap_full": lambda a: self.network.scan_all_ports(a),
            "nmap_vuln": lambda a: self.network.vuln_scan(a),
            "smb_enum": lambda a: self.network.enum_shares(a),
            "stego_analyze": lambda a: self.stego.full_analysis(a),
            "stego_extract": lambda a: self.stego.try_extract(a),
        }

        if tool_name in tool_map:
            try:
                return tool_map[tool_name](args.strip())
            except Exception as e:
                return ToolResult(
                    tool=tool_name, success=False, output="",
                    error=str(e), command=detail
                )

        return self.sys.run(detail)

    def _exec_compare(self, args: str) -> ToolResult:
        parts = args.strip().split()
        if len(parts) >= 2:
            return self.forensics.compare_files(parts[0], parts[1])
        return ToolResult(
            tool="compare", success=False, output="",
            error="Usage: compare <file1> <file2>"
        )

    def available_tools_list(self) -> list[str]:
        tools = []
        check = [
            "nmap", "curl", "gdb", "r2", "objdump", "strings", "xxd",
            "gobuster", "dirb", "dirsearch", "nikto", "whatweb", "sqlmap",
            "hashcat", "john", "steghide", "zsteg", "binwalk", "foremost",
            "exiftool", "pdfinfo", "pdftotext", "enum4linux", "smbclient",
            "tshark", "tcpdump", "ROPgadget", "ropper", "checksec",
            "volatility", "sox", "sshpass", "base64", "python3",
        ]
        for t in check:
            if self.sys.available(t):
                tools.append(t)
        return tools
