"""System-level tools: the basic utilities every CTF needs."""

import os
import subprocess
import shutil
from dataclasses import dataclass
from typing import Optional


@dataclass
class ToolResult:
    tool: str
    success: bool
    output: str
    error: str = ""
    command: str = ""
    return_code: int = -1

    def summary(self) -> str:
        parts = []
        if self.output:
            parts.append(self.output[:5000])
        if self.error:
            parts.append(f"STDERR: {self.error[:1000]}")
        if self.return_code != -1:
            parts.append(f"Exit code: {self.return_code}")
        return "\n".join(parts) if parts else "(no output)"


class SystemTools:
    """Low-level command execution with full local access."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.available_cache: dict[str, bool] = {}

    def run(self, cmd: str, timeout: Optional[int] = None,
            cwd: Optional[str] = None) -> ToolResult:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout or self.timeout, cwd=cwd
            )
            return ToolResult(
                tool="shell",
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr,
                command=cmd,
                return_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool="shell", success=False, output="",
                error=f"Timed out after {timeout or self.timeout}s",
                command=cmd
            )
        except Exception as e:
            return ToolResult(
                tool="shell", success=False, output="",
                error=str(e), command=cmd
            )

    def available(self, tool: str) -> bool:
        if tool not in self.available_cache:
            self.available_cache[tool] = shutil.which(tool) is not None
        return self.available_cache[tool]

    def read_file(self, path: str, nbytes: int = 0) -> ToolResult:
        if not os.path.exists(path):
            return ToolResult(
                tool="read", success=False, output="",
                error=f"File not found: {path}"
            )
        try:
            if nbytes > 0:
                with open(path, "rb") as f:
                    data = f.read(nbytes)
                return ToolResult(
                    tool="read", success=True,
                    output=data.decode("utf-8", errors="replace"),
                    command=f"read {path} ({nbytes} bytes)"
                )
            else:
                with open(path, "r", errors="replace") as f:
                    data = f.read(100000)
                return ToolResult(
                    tool="read", success=True, output=data,
                    command=f"read {path}"
                )
        except Exception as e:
            return ToolResult(
                tool="read", success=False, output="", error=str(e)
            )

    def write_file(self, path: str, content: str) -> ToolResult:
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
            return ToolResult(
                tool="write", success=True, output=f"Written to {path}",
                command=f"write {path}"
            )
        except Exception as e:
            return ToolResult(
                tool="write", success=False, output="", error=str(e)
            )

    def list_dir(self, path: str) -> ToolResult:
        return self.run(f"ls -la {path}")

    def find_files(self, directory: str, pattern: str = "*") -> ToolResult:
        return self.run(f"find {directory} -name '{pattern}' -type f 2>/dev/null")

    def file_info(self, filepath: str) -> ToolResult:
        return self.run(f"file '{filepath}'")

    def strings(self, filepath: str, minlength: int = 4) -> ToolResult:
        return self.run(f"strings -n {minlength} '{filepath}'")

    def hexdump(self, filepath: str, length: int = 256) -> ToolResult:
        return self.run(f"xxd -l {length} '{filepath}'")

    def md5(self, filepath: str) -> ToolResult:
        return self.run(f"md5sum '{filepath}'")

    def sha256(self, filepath: str) -> ToolResult:
        return self.run(f"sha256sum '{filepath}'")

    def base64_encode(self, text: str) -> ToolResult:
        return self.run(f"echo -n '{text}' | base64")

    def base64_decode(self, text: str) -> ToolResult:
        return self.run(f"echo -n '{text}' | base64 -d 2>/dev/null || echo '{text}' | base64 -d 2>/dev/null")

    def curl(self, url: str, method: str = "GET",
             data: Optional[str] = None,
             headers: Optional[dict] = None) -> ToolResult:
        cmd_parts = ["curl", "-s", "-L", "-k", "-i"]
        if method != "GET":
            cmd_parts.append(f"-X {method}")
        if headers:
            for k, v in headers.items():
                cmd_parts.append(f"-H '{k}: {v}'")
        if data:
            if isinstance(data, str) and os.path.isfile(data):
                cmd_parts.append(f"--data-binary @'{data}'")
            else:
                cmd_parts.append(f"--data '{data}'")
        cmd_parts.append(f"'{url}'")
        return self.run(" ".join(cmd_parts), timeout=30)

    def wget(self, url: str, output: str) -> ToolResult:
        return self.run(f"wget -q -O '{output}' '{url}'")

    def chmod(self, path: str, mode: str) -> ToolResult:
        return self.run(f"chmod {mode} '{path}'")

    def extract_archive(self, archive: str, dest: str) -> ToolResult:
        os.makedirs(dest, exist_ok=True)
        return self.run(f"cd '{dest}' && tar xf '{archive}' 2>/dev/null || "
                       f"unzip -o '{archive}' 2>/dev/null || "
                       f"7z x '{archive}' -o'{dest}' 2>/dev/null")
