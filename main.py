import sys
import math
import re
import os

def calculate_entropy(data):
    """
    Calculates Shannon Entropy.
    Range: 0.0 - 8.0
    High entropy (>7.5) indicates packed or encrypted data.
    """
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_strings(data, min_length=4):
    """
    Extracts printable ASCII sequences.
    """
    results = []
    pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
    
    for match in pattern.finditer(data):
        try:
            decoded = match.group().decode('utf-8')
            results.append(decoded)
        except:
            pass
    return results

def analyze_file(filepath):
    print(f"\n[*] STARTING BINARY ANALYSIS TARGET: {os.path.basename(filepath)}")
    print("=" * 60)
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            
        # 1. File Size Analysis
        file_size = len(data)
        print(f"[*] File Size      : {file_size / 1024:.2f} KB")
        
        # 2. Entropy Analysis
        entropy = calculate_entropy(data)
        print(f"[*] Entropy Score  : {entropy:.4f} / 8.0000")
        
        if entropy > 7.5:
            print("    [!] ALERT: High Entropy detected! File is likely PACKED or ENCRYPTED.")
        elif entropy < 5.0:
            print("    [-] Low Entropy. File likely contains plain text or simple code.")
        else:
            print("    [+] Standard executable entropy levels.")

        # 3. Artifact Extraction (IP, URL, Keywords)
        print("\n[*] SCANNING FOR ARTIFACTS...")
        strings = extract_strings(data)
        
        # Filtering for critical keywords
        potential_secrets = [s for s in strings if "http" in s or "@" in s or "key" in s.lower() or "password" in s.lower() or "192.168" in s]
        
        if potential_secrets:
            print(f"[!] CRITICAL: Found {len(potential_secrets)} potential sensitive artifacts:")
            for s in potential_secrets[:10]: # Limit display to 10 items
                print(f"    -> {s}")
            if len(potential_secrets) > 10:
                print(f"    ... and {len(potential_secrets) - 10} more.")
        else:
            print(f"[-] No critical artifacts found in {len(strings)} strings extracted.")

    except FileNotFoundError:
        print("[!] ERROR: File not found.")
    except Exception as e:
        print(f"[!] ERROR: {e}")
    
    print("=" * 60)
    print("[*] ANALYSIS COMPLETE.")

if __name__ == "__main__":
    target_file = input("Target File Path > ")
    target_file = target_file.strip('"') 
    
    if target_file:
        analyze_file(target_file)
    else:
        print("[!] No file selected.")
    
    input("\nPress Enter to exit...")