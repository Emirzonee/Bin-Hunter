"""
Bin-Hunter — Static Binary Analysis Tool

Analyzes binary files using Shannon entropy to detect packing
or encryption, extracts readable strings, and scans for
embedded artifacts like URLs, IPs, and credentials.

Usage:
    python hunter.py suspicious.exe
    python hunter.py malware.bin --strings 6
    python hunter.py payload.dll --json
"""

import sys
import os
import re
import math
import json
import argparse
from collections import Counter


# common file signatures (magic bytes)
SIGNATURES = {
    b"\x4d\x5a": "PE Executable (EXE/DLL)",
    b"\x7f\x45\x4c\x46": "ELF Binary (Linux)",
    b"\xfe\xed\xfa": "Mach-O Binary (macOS)",
    b"\x50\x4b\x03\x04": "ZIP Archive",
    b"\x52\x61\x72\x21": "RAR Archive",
    b"\x1f\x8b": "GZIP Archive",
    b"\x89\x50\x4e\x47": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"\x25\x50\x44\x46": "PDF Document",
}


def detect_filetype(data):
    """Identify file type from magic bytes."""
    for sig, name in SIGNATURES.items():
        if data[:len(sig)] == sig:
            return name
    return "Unknown"


def shannon_entropy(data):
    """
    Calculate Shannon entropy of byte data.
    Returns a value between 0.0 and 8.0.
    Above 7.5 usually means packed/encrypted content.
    """
    if not data:
        return 0.0

    freq = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def chunk_entropy(data, chunk_size=256):
    """Calculate entropy per chunk to find high-entropy sections."""
    results = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) < chunk_size // 2:
            break
        e = shannon_entropy(chunk)
        results.append({"offset": i, "entropy": round(e, 3)})
    return results


def extract_strings(data, min_length=4):
    """Pull readable ASCII strings from binary data."""
    pattern = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}")
    strings = []
    for match in pattern.finditer(data):
        try:
            strings.append(match.group().decode("utf-8"))
        except UnicodeDecodeError:
            pass
    return strings


def find_artifacts(strings):
    """Search extracted strings for interesting patterns."""
    artifacts = {
        "urls": [],
        "ips": [],
        "emails": [],
        "suspicious_keywords": [],
    }

    ip_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    keywords = ["password", "passwd", "secret", "token", "api_key",
                "private", "credential", "auth", "login", "admin"]

    for s in strings:
        if s.startswith("http://") or s.startswith("https://"):
            artifacts["urls"].append(s)
        if ip_re.search(s):
            artifacts["ips"].extend(ip_re.findall(s))
        if email_re.search(s):
            artifacts["emails"].extend(email_re.findall(s))
        for kw in keywords:
            if kw in s.lower() and s not in artifacts["suspicious_keywords"]:
                artifacts["suspicious_keywords"].append(s)

    # deduplicate
    for key in artifacts:
        artifacts[key] = list(dict.fromkeys(artifacts[key]))

    return artifacts


def classify_entropy(value):
    """Return a human-readable classification."""
    if value > 7.5:
        return "PACKED/ENCRYPTED — high entropy suggests obfuscation"
    elif value > 6.0:
        return "COMPILED — typical for native executables"
    elif value > 4.0:
        return "MIXED — contains both code and data sections"
    else:
        return "PLAINTEXT — low complexity, likely text or simple data"


def analyze(filepath, min_str_len=4):
    """Run full analysis on a binary file."""
    with open(filepath, "rb") as f:
        data = f.read()

    file_size = len(data)
    filetype = detect_filetype(data)
    entropy = shannon_entropy(data)
    classification = classify_entropy(entropy)
    strings = extract_strings(data, min_str_len)
    artifacts = find_artifacts(strings)

    # find peak entropy section
    chunks = chunk_entropy(data)
    peak = max(chunks, key=lambda c: c["entropy"]) if chunks else None

    return {
        "file": os.path.basename(filepath),
        "size_bytes": file_size,
        "size_kb": round(file_size / 1024, 2),
        "filetype": filetype,
        "entropy": round(entropy, 4),
        "classification": classification,
        "peak_entropy": peak,
        "total_strings": len(strings),
        "artifacts": artifacts,
    }


def print_report(report):
    """Display analysis results."""
    print(f"\n  File:     {report['file']}")
    print(f"  Size:     {report['size_kb']} KB")
    print(f"  Type:     {report['filetype']}")
    print("=" * 50)

    print(f"  Entropy:  {report['entropy']} / 8.0")
    print(f"  Verdict:  {report['classification']}")

    if report["peak_entropy"]:
        p = report["peak_entropy"]
        print(f"  Peak:     {p['entropy']} at offset 0x{p['offset']:X}")

    print(f"\n  Strings extracted: {report['total_strings']}")

    art = report["artifacts"]
    total_artifacts = sum(len(v) for v in art.values())

    if total_artifacts == 0:
        print("  Artifacts: none found")
    else:
        print(f"  Artifacts: {total_artifacts} found")
        if art["urls"]:
            print(f"\n  URLs ({len(art['urls'])}):")
            for u in art["urls"][:10]:
                print(f"    {u}")
        if art["ips"]:
            print(f"\n  IPs ({len(art['ips'])}):")
            for ip in art["ips"][:10]:
                print(f"    {ip}")
        if art["emails"]:
            print(f"\n  Emails ({len(art['emails'])}):")
            for e in art["emails"][:10]:
                print(f"    {e}")
        if art["suspicious_keywords"]:
            print(f"\n  Suspicious strings ({len(art['suspicious_keywords'])}):")
            for s in art["suspicious_keywords"][:10]:
                print(f"    {s}")

    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(description="Bin-Hunter — Static Binary Analyzer")
    parser.add_argument("file", help="path to binary file")
    parser.add_argument("--strings", type=int, default=4,
                        help="minimum string length to extract (default: 4)")
    parser.add_argument("--json", action="store_true",
                        help="output results as JSON")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    report = analyze(args.file, args.strings)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()