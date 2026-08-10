"""Binary analysis and exploitation tools."""

from typing import Optional
from .system import SystemTools, ToolResult


class BinaryTools:
    def __init__(self, sys_tools: SystemTools):
        self.sys = sys_tools

    def analyze(self, filepath: str) -> ToolResult:
        results = []
        info = self.sys.file_info(filepath)
        results.append(f"FILE: {info.output.strip()}")

        checksec = self.sys.run(f"checksec --file='{filepath}' 2>/dev/null "
                                f"|| checksec '{filepath}' 2>/dev/null")
        if checksec.success and checksec.output.strip():
            results.append(f"CHECKSEC:\n{checksec.output.strip()}")

        strings_out = self.sys.strings(filepath, minlength=6)
        if strings_out.success:
            interesting = []
            for line in strings_out.output.split("\n"):
                low = line.lower()
                if any(k in low for k in [
                    "flag{", "ctf{", "password", "secret", "key",
                    "admin", "root", "shell", "/bin/", "libc",
                    "format", "vuln", "exploit", "%x", "%n", "%s",
                ]):
                    interesting.append(line.strip())
            if interesting:
                results.append(f"INTERESTING STRINGS:\n" + "\n".join(interesting[:30]))

        entropy = self.sys.run(f"binwalk -E '{filepath}' 2>/dev/null | head -5")
        if entropy.success and entropy.output.strip():
            results.append(f"ENTROPY:\n{entropy.output.strip()}")

        return ToolResult(
            tool="binary_analyze", success=True,
            output="\n\n".join(results),
            command=f"analyze {filepath}"
        )

    def disassemble(self, filepath: str, func: str = "",
                    backend: str = "r2") -> ToolResult:
        if backend == "r2" and self.sys.available("r2"):
            flags = "-q -c"
            if func:
                cmd = f"r2 {flags} 'aaa; s {func}; pdf' '{filepath}'"
            else:
                cmd = f"r2 {flags} 'aaa; afl' '{filepath}'"
            return self.sys.run(cmd, timeout=30)
        elif self.sys.available("objdump"):
            if func:
                cmd = f"objdump -d -M intel '{filepath}' | grep -A 50 '<{func}>:'"
            else:
                cmd = f"objdump -d -M intel '{filepath}' | head -200"
            return self.sys.run(cmd, timeout=15)
        return ToolResult(
            tool="disasm", success=False, output="",
            error="No disassembler available (need r2 or objdump)"
        )

    def run_with_args(self, filepath: str, args: str = "",
                      timeout: int = 10) -> ToolResult:
        self.sys.chmod(filepath, "+x")
        cmd = f"timeout {timeout} '{filepath}' {args} 2>&1"
        return self.sys.run(cmd, timeout=timeout + 2)

    def debug(self, filepath: str, commands: str = "info registers") -> ToolResult:
        if self.sys.available("gdb"):
            cmd = (f"echo '{commands}\nquit' | gdb -q '{filepath}' 2>/dev/null")
            return self.sys.run(cmd, timeout=15)
        return ToolResult(
            tool="debug", success=False, output="",
            error="gdb not available"
        )

    def strace(self, filepath: str, args: str = "",
               timeout: int = 10) -> ToolResult:
        cmd = f"timeout {timeout} strace -f '{filepath}' {args} 2>&1 | head -200"
        return self.sys.run(cmd, timeout=timeout + 2)

    def ltrace(self, filepath: str, args: str = "",
               timeout: int = 10) -> ToolResult:
        cmd = f"timeout {timeout} ltrace -f '{filepath}' {args} 2>&1 | head -200"
        return self.sys.run(cmd, timeout=timeout + 2)

    def extract_libc(self, filepath: str) -> ToolResult:
        return self.sys.run(
            f"ldd '{filepath}' 2>/dev/null"
        )

    def find_rop_gadgets(self, filepath: str) -> ToolResult:
        if self.sys.available("ROPgadget"):
            return self.sys.run(f"ROPgadget --binary '{filepath}' | head -50", timeout=30)
        if self.sys.available("ropper"):
            return self.sys.run(f"ropper --file '{filepath}' --search pop 2>/dev/null | head -30", timeout=30)
        return ToolResult(
            tool="rop", success=False, output="",
            error="No ROP tool available (need ROPgadget or ropper)"
        )
