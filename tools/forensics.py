"""Forensics tools: file analysis, extraction, memory analysis."""

from typing import Optional
from .system import SystemTools, ToolResult


class ForensicsTools:
    def __init__(self, sys_tools: SystemTools):
        self.sys = sys_tools

    def full_analysis(self, filepath: str) -> ToolResult:
        results = []

        info = self.sys.file_info(filepath)
        results.append(f"FILE: {info.output.strip()}")

        strings_result = self.sys.strings(filepath, minlength=4)
        if strings_result.success:
            interesting = []
            for line in strings_result.output.split("\n"):
                low = line.lower()
                if any(k in low for k in [
                    "flag{", "ctf{", "password", "secret", "key",
                    "http", "ftp", "user", "admin", "login",
                    "BEGIN", "END", "PK", "Rar",
                ]):
                    interesting.append(line.strip())
            if interesting:
                results.append("INTERESTING STRINGS:\n" + "\n".join(interesting[:30]))

        meta = self.sys.run(f"exiftool '{filepath}' 2>/dev/null")
        if meta.success and meta.output.strip():
            results.append(f"METADATA:\n{meta.output.strip()[:2000]}")

        return ToolResult(
            tool="forensics_analyze", success=True,
            output="\n\n".join(results),
            command=f"forensics {filepath}"
        )

    def binwalk_extract(self, filepath: str, dest_dir: str) -> ToolResult:
        return self.sys.run(
            f"binwalk -e -C '{dest_dir}' '{filepath}' 2>&1",
            timeout=60
        )

    def foremost_extract(self, filepath: str, dest_dir: str) -> ToolResult:
        return self.sys.run(
            f"foremost -i '{filepath}' -o '{dest_dir}' 2>&1",
            timeout=60
        )

    def extract_archives(self, filepath: str, dest_dir: str) -> ToolResult:
        return self.sys.extract_archive(filepath, dest_dir)

    def hex_analysis(self, filepath: str, offset: int = 0,
                     length: int = 512) -> ToolResult:
        cmd = f"xxd -s {offset} -l {length} '{filepath}'"
        return self.sys.run(cmd)

    def compare_files(self, file1: str, file2: str) -> ToolResult:
        diff = self.sys.run(f"diff '{file1}' '{file2}' | head -50")
        cmp = self.sys.run(f"cmp -l '{file1}' '{file2}' | head -20")
        xor = self.sys.run(
            f"python3 -c \""
            f"a=open('{file1}','rb').read();"
            f"b=open('{file2}','rb').read();"
            f"l=min(len(a),len(b));"
            f"print(f'Lengths: {{len(a)}} vs {{len(b)}}');"
            f"diffs=sum(1 for i in range(l) if a[i]!=b[i]);"
            f"print(f'Byte differences: {{diffs}}')"
            f"\" 2>/dev/null"
        )
        parts = []
        if diff.success and diff.output:
            parts.append(f"DIFF:\n{diff.output[:2000]}")
        if cmp.success and cmp.output:
            parts.append(f"CMP:\n{cmp.output[:1000]}")
        if xor.success and xor.output:
            parts.append(f"COMPARE:\n{xor.output}")
        return ToolResult(
            tool="compare", success=True,
            output="\n\n".join(parts) or "Files are identical",
            command=f"compare {file1} {file2}"
        )

    def analyze_pcap(self, filepath: str) -> ToolResult:
        results = []
        tshark = self.sys.run(
            f"tshark -r '{filepath}' -T fields "
            f"-e frame.protocols -e ip.src -e ip.dst "
            f"-e tcp.port -e udp.port -e http.host "
            f"-e http.request.uri -e dns.qry.name "
            f"2>/dev/null | head -100"
        )
        if tshark.success and tshark.output.strip():
            results.append(f"PACKET SUMMARY:\n{tshark.output[:3000]}")

        http = self.sys.run(
            f"tshark -r '{filepath}' -Y http -T fields "
            f"-e http.host -e http.request.method "
            f"-e http.request.uri -e http.file_data "
            f"2>/dev/null | head -50"
        )
        if http.success and http.output.strip():
            results.append(f"HTTP TRAFFIC:\n{http.output[:3000]}")

        strings_result = self.sys.run(
            f"strings '{filepath}' | grep -iE 'flag\\{{|ctf\\{{|password|secret|key|http|user'"
        )
        if strings_result.success and strings_result.output.strip():
            results.append(f"STRINGS:\n{strings_result.output[:2000]}")

        streams = self.sys.run(
            f"tshark -r '{filepath}' -z conv,tcp 2>/dev/null | head -20"
        )
        if streams.success and streams.output.strip():
            results.append(f"TCP STREAMS:\n{streams.output[:1000]}")

        return ToolResult(
            tool="pcap", success=True,
            output="\n\n".join(results) or "No results from pcap analysis",
            command=f"analyze_pcap {filepath}"
        )

    def memory_dump_analysis(self, filepath: str) -> ToolResult:
        results = []
        strings_result = self.sys.run(
            f"strings '{filepath}' | grep -iE "
            f"'flag\\{{|ctf\\{{|password|secret|/bin/bash|/etc/shadow'"
        )
        if strings_result.success and strings_result.output.strip():
            results.append(f"INTERESTING STRINGS:\n{strings_result.output[:3000]}")

        processes = self.sys.run(
            f"strings '{filepath}' | grep -iE '^[a-z]+\\s+\\d+\\s+\\d+\\s+'"
        )
        if processes.success and processes.output.strip():
            results.append(f"PROCESS LISTINGS:\n{processes.output[:2000]}")

        if self.sys.available("volatility"):
            vol = self.sys.run(
                f"volatility -f '{filepath}' imageinfo 2>/dev/null | head -10",
                timeout=60
            )
            if vol.success and vol.output.strip():
                results.append(f"VOLATILITY:\n{vol.output[:1000]}")

        return ToolResult(
            tool="memdump", success=True,
            output="\n\n".join(results),
            command=f"analyze_memdump {filepath}"
        )
