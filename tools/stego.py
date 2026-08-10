"""Steganography tools: image and audio analysis."""

from typing import Optional
from .system import SystemTools, ToolResult


class StegoTools:
    def __init__(self, sys_tools: SystemTools):
        self.sys = sys_tools

    def full_analysis(self, filepath: str) -> ToolResult:
        results = []

        info = self.sys.file_info(filepath)
        results.append(f"FILE: {info.output.strip()}")

        meta = self.sys.run(f"exiftool '{filepath}' 2>/dev/null")
        if meta.success and meta.output.strip():
            results.append(f"METADATA:\n{meta.output[:2000]}")

        strings_result = self.sys.run(
            f"strings '{filepath}' | grep -iE 'flag\\{{|ctf\\{{|password|secret|key|comment'"
        )
        if strings_result.success and strings_result.output.strip():
            results.append(f"STRINGS:\n{strings_result.output[:1000]}")

        if filepath.lower().endswith(('.png', '.jpg', '.jpeg')):
            self._image_analysis(filepath, results)

        if filepath.lower().endswith(('.wav', '.mp3', '.flac')):
            self._audio_analysis(filepath, results)

        if filepath.lower().endswith('.pdf'):
            self._pdf_analysis(filepath, results)

        return ToolResult(
            tool="stego_analyze", success=True,
            output="\n\n".join(results),
            command=f"stego_analyze {filepath}"
        )

    def _image_analysis(self, filepath: str, results: list):
        if self.sys.available("zsteg"):
            zsteg = self.sys.run(
                f"zsteg -a '{filepath}' 2>/dev/null | head -40",
                timeout=30
            )
            if zsteg.success and zsteg.output.strip():
                results.append(f"ZSTEG:\n{zsteg.output[:2000]}")

        if self.sys.available("steghide"):
            info = self.sys.run(
                f"steghide info '{filepath}' 2>/dev/null"
            )
            if info.success and info.output.strip():
                results.append(f"STEGHIDE INFO:\n{info.output[:500]}")
                extract = self.sys.run(
                    f"steghide extract -sf '{filepath}' -p '' -f -xf /tmp/_ctf_stego_extract 2>/dev/null"
                )
                if extract.success:
                    results.append("Steghide: empty password extract succeeded!")

        if self.sys.available("binwalk"):
            bw = self.sys.run(
                f"binwalk '{filepath}' 2>/dev/null | head -20"
            )
            if bw.success and bw.output.strip():
                results.append(f"BINWALK:\n{bw.output[:1000]}")

        self._lsb_analysis(filepath, results)

    def _lsb_analysis(self, filepath: str, results: list):
        script = f"""
from PIL import Image
try:
    img = Image.open('{filepath}')
    pixels = list(img.getdata())
    bits = ''
    for p in pixels[:1000]:
        for channel in p[:3]:
            bits += str(channel & 1)
    text = ''
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i+8]
        char = chr(int(byte, 2))
        if 32 <= ord(char) <= 126:
            text += char
        else:
            text += '.'
    if any(c.isalpha() for c in text[:50]):
        print(f'LSB first 50 chars: {{text[:50]}}')
    # Check for hidden data at end
    data_bits = ''
    for p in pixels:
        for channel in p[:3]:
            data_bits += str(channel & 1)
    decoded = ''
    for i in range(0, min(len(data_bits), 8000) - 7, 8):
        byte = data_bits[i:i+8]
        c = chr(int(byte, 2))
        if 32 <= ord(c) <= 126 or c in '\\n\\r\\t':
            decoded += c
        else:
            decoded += '.'
    import re
    flag_match = re.search(r'flag\\{{[^}}]+\\}}', decoded, re.IGNORECASE)
    if flag_match:
        print(f'FLAG FOUND IN LSB: {{flag_match.group()}}')
    ctf_match = re.search(r'ctf\\{{[^}}]+\\}}', decoded, re.IGNORECASE)
    if ctf_match:
        print(f'CTF FOUND IN LSB: {{ctf_match.group()}}')
except Exception as e:
    print(f'LSB analysis error: {{e}}')
"""
        lsb = self.sys.run(f"python3 -c '''{script}'''", timeout=15)
        if lsb.success and lsb.output.strip():
            results.append(f"LSB:\n{lsb.output[:1000]}")

    def _audio_analysis(self, filepath: str, results: list):
        if self.sys.available("sox"):
            spec = self.sys.run(
                f"sox '{filepath}' -n stat 2>&1"
            )
            if spec.success:
                results.append(f"AUDIO STATS:\n{spec.output[:500]}")

        spectro = self.sys.run(
            f"file '{filepath}' && strings '{filepath}' | grep -iE 'flag|ctf|key|secret'"
        )
        if spectro.success and spectro.output.strip():
            results.append(f"AUDIO STRINGS:\n{spectro.output[:500]}")

    def _pdf_analysis(self, filepath: str, results: list):
        if self.sys.available("pdfinfo"):
            info = self.sys.run(f"pdfinfo '{filepath}' 2>/dev/null")
            if info.success:
                results.append(f"PDF INFO:\n{info.output[:500]}")

        if self.sys.available("pdftotext"):
            text = self.sys.run(f"pdftotext '{filepath}' - 2>/dev/null")
            if text.success and text.output.strip():
                results.append(f"PDF TEXT:\n{text.output[:2000]}")

        self.sys.run(f"binwalk '{filepath}' 2>/dev/null | head -10")

    def try_extract(self, filepath: str, password: str = "",
                    dest: str = "/tmp/_ctf_stego_extracted") -> ToolResult:
        import os
        os.makedirs(dest, exist_ok=True)
        results = []

        if self.sys.available("steghide"):
            cmd = f"steghide extract -sf '{filepath}' -p '{password}' -xf '{dest}/steghide_out' -f 2>/dev/null"
            r = self.sys.run(cmd)
            if r.success:
                results.append(f"Steghide extraction succeeded")

        if self.sys.available("zsteg"):
            r = self.sys.run(f"zsteg -a '{filepath}' -o '{dest}/zsteg_out' 2>/dev/null")
            if r.success:
                results.append(f"Zsteg extraction succeeded")

        if self.sys.available("binwalk"):
            r = self.sys.run(f"binwalk -e -C '{dest}' '{filepath}' 2>/dev/null")
            if r.success:
                results.append(f"Binwalk extraction succeeded")

        list_out = self.sys.run(f"find '{dest}' -type f 2>/dev/null")
        if list_out.success and list_out.output.strip():
            results.append(f"Extracted files:\n{list_out.output[:1000]}")

        return ToolResult(
            tool="stego_extract", success=bool(results),
            output="\n".join(results) or "No extraction succeeded",
            command=f"stego_extract {filepath}"
        )
