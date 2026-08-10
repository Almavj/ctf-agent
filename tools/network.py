"""Network analysis tools."""

from typing import Optional
from .system import SystemTools, ToolResult


class NetworkTools:
    def __init__(self, sys_tools: SystemTools):
        self.sys = sys_tools

    def scan_target(self, target: str) -> ToolResult:
        return self.sys.run(
            f"nmap -sV -sC -T4 --top-ports 1000 '{target}' 2>/dev/null",
            timeout=120
        )

    def scan_all_ports(self, target: str) -> ToolResult:
        return self.sys.run(
            f"nmap -sV -sC -A -p- -T4 '{target}' 2>/dev/null",
            timeout=300
        )

    def quick_scan(self, target: str) -> ToolResult:
        return self.sys.run(
            f"nmap -sV -T4 --top-ports 100 '{target}' 2>/dev/null",
            timeout=60
        )

    def udp_scan(self, target: str) -> ToolResult:
        return self.sys.run(
            f"nmap -sU --top-ports 50 -T4 '{target}' 2>/dev/null",
            timeout=90
        )

    def vuln_scan(self, target: str, ports: str = "") -> ToolResult:
        port_flag = f"-p {ports}" if ports else ""
        return self.sys.run(
            f"nmap --script vuln {port_flag} -T4 '{target}' 2>/dev/null",
            timeout=180
        )

    def enum_shares(self, target: str) -> ToolResult:
        if self.sys.available("enum4linux"):
            return self.sys.run(f"enum4linux -a '{target}' 2>/dev/null | head -80", timeout=60)
        return self.sys.run(
            f"smbclient -L '{target}' -N 2>/dev/null || "
            f"nmap --script smb-enum-shares -p 445 '{target}' 2>/dev/null",
            timeout=30
        )

    def capture_packets(self, interface: str = "eth0",
                        duration: int = 10) -> ToolResult:
        return self.sys.run(
            f"timeout {duration} tcpdump -i {interface} -w /tmp/_ctf_capture.pcap "
            f"-c 100 2>/dev/null"
        )

    def analyze_pcap(self, filepath: str) -> ToolResult:
        from .forensics import ForensicsTools
        ft = ForensicsTools(self.sys)
        return ft.analyze_pcap(filepath)

    def port_scan_range(self, target: str, start: int,
                        end: int) -> ToolResult:
        return self.sys.run(
            f"nmap -p {start}-{end} -T4 '{target}' 2>/dev/null",
            timeout=120
        )
