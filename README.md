# Bin-Hunter

Static binary analysis tool that calculates Shannon entropy, extracts readable strings, and scans for embedded artifacts like URLs, IP addresses, and credentials. Helps determine if a file is packed, encrypted, or contains suspicious content.

## What It Does

Feed it any binary file and it will tell you:

- **File type** from magic bytes (PE, ELF, ZIP, PDF, etc.)
- **Entropy score** (0-8) with classification (plaintext / compiled / packed / encrypted)
- **Peak entropy section** to locate obfuscated regions
- **Extracted strings** with configurable minimum length
- **Artifacts** found in strings: URLs, IPs, emails, and suspicious keywords

## Usage

```bash
python hunter.py suspicious.exe
```
```
  File:     suspicious.exe
  Size:     142.38 KB
  Type:     PE Executable (EXE/DLL)
==================================================
  Entropy:  7.6812 / 8.0
  Verdict:  PACKED/ENCRYPTED - high entropy suggests obfuscation
  Peak:     7.9341 at offset 0x4200

  Strings extracted: 347
  Artifacts: 5 found

  URLs (2):
    http://evil-c2.example.com/beacon
    https://pastebin.com/raw/abc123

  IPs (2):
    192.168.1.100
    10.0.0.55

  Suspicious strings (1):
    password=admin123
==================================================
```

**JSON output:**
```bash
python hunter.py sample.bin --json
```

**Custom string length:**
```bash
python hunter.py payload.dll --strings 8
```

## How Entropy Analysis Works

Shannon entropy measures the randomness of data on a scale of 0 to 8 bits per byte.

| Entropy Range | Meaning |
|--------------|---------|
| 0.0 - 4.0   | Plaintext, simple data, lots of repetition |
| 4.0 - 6.0   | Mixed content, scripts, interpreted code |
| 6.0 - 7.5   | Compiled native code (normal executables) |
| 7.5 - 8.0   | Packed, compressed, or encrypted data |

Malware authors often pack their binaries to avoid signature detection. This raises entropy close to 8.0 which is a strong indicator that something is obfuscated.

## Installation

```bash
git clone https://github.com/Emirzonee/Bin-Hunter.git
cd Bin-Hunter
```

No external dependencies. Uses only Python standard library.

## Project Structure

```
Bin-Hunter/
|-- hunter.py         # Main analysis script
|-- .gitignore
|-- LICENSE
|-- README.md
```

## Disclaimer

For educational purposes and authorized security research only.

## License

MIT