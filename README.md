# CTF Agent - Universal Autonomous Flag Capture Engine

An AI agent that solves ANY type of CTF challenge. Give it a file, IP, URL, or directory and it automatically figures out what it is, picks the right tools, and works toward capturing the flag.

Handles binary exploitation, reverse engineering, forensics, cryptography, web exploitation, steganography, network analysis, and misc challenges.

## How It Works

```
    Input (file / IP / URL / directory)
                 │
     ┌───────────▼───────────┐
     │    Classifier          │  Detects challenge type, file type, MIME
     └───────────┬───────────┘
                 │
     ┌───────────▼───────────┐
     │   Initial Recon        │  Auto-runs the right analysis for the type
     └───────────┬───────────┘
                 │
     ┌───────────▼───────────┐
     │   LLM Planner          │  Llama 3.2 picks the best next action
     └───────────┬───────────┘
                 │
     ┌───────────▼───────────┐
     │   Executor             │  Full local access: bash, tools, binaries
     └───────────┬───────────┘
                 │
     ┌───────────▼───────────┐
     │   Flag Parser          │  Regex detection across 10+ flag formats
     └───────────┬───────────┘
                 │
          Flag found? ─── No ──→ feed back to LLM
                 │
                Yes → done
```

## Supported Challenge Types

| Type | What it handles |
|---|---|
| **Binary / Pwn** | ELF analysis, checksec, disassembly, ROP gadgets, gdb debugging, strace |
| **Reverse Engineering** | Binary analysis, string extraction, function identification |
| **Forensics** | File carving, metadata, pcap analysis, memory dumps, archive extraction |
| **Crypto** | Base64, ROT ciphers, XOR brute force, hash cracking, RSA, Vigenere |
| **Web** | SQL injection, LFI, command injection, directory bruteforce, nikto |
| **Network** | nmap scanning, pcap analysis, SMB enumeration, traffic extraction |
| **Steganography** | LSB analysis, zsteg, steghide, metadata, binwalk, PDF analysis |
| **Misc** | Adaptive: tries tools based on what it finds |

## Prerequisites

- **Python 3.10+**
- **Ollama** with a model: `ollama pull llama3.2`
- **System tools** (install what you can, the agent adapts):

```bash
# Essential
sudo apt install nmap strings file python3-pip

# Binary analysis
sudo apt install gdb binutils radare2

# Web
sudo apt install gobuster nikto sqlmap

# Forensics
sudo apt install binwalk foremost exiftool tcpdump tshark wireshark

# Steganography
sudo apt install steghide zsteg

# Crypto
sudo apt install john hashcat

# Misc
sudo apt install sshpass enum4linux
```

## Setup

```bash
pip install -r requirements.txt
ollama pull llama3.2
```

## Usage

```bash
python agent.py <TARGET>
```

### Examples

```bash
# Binary exploitation / reverse engineering
python agent.py ./vuln_binary
python agent.py ./ransomware.exe

# Forensics
python agent.py ./evidence.pcap
python agent.py ./memory.dump
python agent.py ./suspicious_file

# Cryptography
python agent.py ./encrypted.txt
python agent.py "U2FsdGVkX1+abc123..."

# Web
python agent.py http://target.local
python agent.py 10.10.10.1

# Steganography
python agent.py ./mystery.png
python agent.py ./hidden_audio.wav

# Directory challenge
python agent.py ./challenge_files/

# Use a bigger model
python agent.py ./binary --model llama3.2:7b --max-steps 80
```

### CLI Options

| Flag | Default | Description |
|---|---|---|
| `target` | (required) | File, directory, IP, or URL |
| `--model` | llama3.2 | Ollama model |
| `--max-steps` | 50 | Max steps before stopping |
| `--step-timeout` | 60 | Seconds per command |
| `--state-dir` | ./state | Where to save state |
| `--ollama-url` | localhost:11434 | Ollama endpoint |

## What Tools It Uses

The agent detects which tools are installed and adapts. More tools = better results:

**Always available** (built-in): strings, file, cat, xxd, curl, python3, base64, md5sum, find, grep

**If installed**: nmap, gdb, r2, objdump, gobuster, nikto, sqlmap, hashcat, john, steghide, zsteg, binwalk, foremost, exiftool, tshark, enum4linux, ROPgadget, ropper, checksec, volatility

## Output

All state saved to `./state/`:

```
state/
├── memory.json     # Full trajectory, flags, lessons
└── run.json        # Detailed step log
```

## Architecture

```
agent.py            Main loop: classify → recon → plan → execute → repeat
classifier.py       Auto-detects challenge type from input
planner.py          LLM prompts, JSON parsing, strategy
executor.py         Routes actions to the right tool module
memory.py           State persistence, trajectory, context building
flag_parser.py      Regex extraction for 10+ flag formats
tools/
├── system.py       Base execution engine (full local access)
├── binary.py       Binary analysis, disassembly, debugging
├── forensics.py    File analysis, pcap, memory dumps
├── crypto.py       Encoding detection, hash cracking, ciphers
├── web.py          HTTP testing, injection, directory busting
├── network.py      Port scanning, SMB, packet capture
└── stego.py        Image/audio analysis, LSB, extraction
```

## RAM Usage

- Agent itself: <100MB
- LLM (llama3.2 7B): ~4GB
- Total on a 16GB laptop: comfortable

## License

For educational and authorized security testing only.
