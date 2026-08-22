"""
CyberQwen-AI: Active CTF Investigation & Auto-Solver Engine
Performs automated multi-stage solving attempts across Crypto, Forensics, Reverse Engineering, and Web.
"""

import re
import base64
import binascii
import string
from typing import Dict, Any, List, Optional, Tuple

FLAG_PATTERN = re.compile(r"(FLAG\{[^}]+\}|CTF\{[^}]+\}|picoCTF\{[^}]+\}|HTB\{[^}]+\}|flag\{[^}]+\}|cyber\{[^}]+\})", re.IGNORECASE)

def rot_decode(text: str, shift: int) -> str:
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            res.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            res.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
        else:
            res.append(c)
    return "".join(res)

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def single_byte_xor_search(data: bytes) -> List[Tuple[int, str]]:
    findings = []
    for key in range(1, 256):
        try:
            dec = bytes([b ^ key for b in data])
            dec_str = dec.decode("utf-8", errors="ignore")
            matches = FLAG_PATTERN.findall(dec_str)
            for m in matches:
                findings.append((key, m))
        except Exception:
            pass
    return findings

class ActiveCTFSolver:
    def __init__(self):
        self.actions_performed = []
        self.hypotheses = []
        self.recovered_artifacts = []
        self.discovered_flags = []

    def log_action(self, action_desc: str):
        if action_desc not in self.actions_performed:
            self.actions_performed.append(action_desc)

    def log_hypothesis(self, finding: str, hypothesis: str, test: str, result: str):
        self.hypotheses.append({
            "finding": finding,
            "hypothesis": hypothesis,
            "test": test,
            "result": result
        })

    def solve_crypto_strings(self, text: str) -> List[str]:
        """Attempts multi-encoding decoding (Base64, Base32, Hex, ROT13, Caesar, XOR)."""
        found_flags = []

        # 1. Direct Flag
        for f in FLAG_PATTERN.findall(text):
            found_flags.append(f)
            self.log_action(f"Extracted direct flag pattern: `{f}`")

        # 2. Base64
        b64_matches = re.findall(r"([A-Za-z0-9+/]{8,}={0,2})", text)
        if b64_matches:
            self.log_action(f"Scanned {len(b64_matches)} Base64 candidates")
        for b64_str in b64_matches[:15]:
            try:
                dec = base64.b64decode(b64_str).decode("utf-8", errors="ignore").strip()
                for f in FLAG_PATTERN.findall(dec):
                    found_flags.append(f)
                    self.log_action(f"Decoded Base64 flag: `{f}`")
                    self.log_hypothesis(
                        finding=f"Base64 string `{b64_str[:20]}...` in text",
                        hypothesis="Encodes obfuscated flag or password",
                        test="Attempt Base64 decoding",
                        result=f"Success -> `{f}`"
                    )
            except Exception:
                pass

        # 3. Base32
        b32_matches = re.findall(r"([A-Z2-7]{10,}={0,6})", text)
        for b32_str in b32_matches[:5]:
            try:
                dec = base64.b32decode(b32_str).decode("utf-8", errors="ignore").strip()
                for f in FLAG_PATTERN.findall(dec):
                    found_flags.append(f)
                    self.log_action(f"Decoded Base32 flag: `{f}`")
            except Exception:
                pass

        # 4. Hex Strings
        hex_matches = re.findall(r"(?:0x)?([0-9a-fA-F]{16,})", text)
        for h in hex_matches[:10]:
            try:
                dec = bytes.fromhex(h).decode("utf-8", errors="ignore")
                for f in FLAG_PATTERN.findall(dec):
                    found_flags.append(f)
                    self.log_action(f"Decoded Hex byte stream: `{f}`")
            except Exception:
                pass

        # 5. ROT13 & Caesar shifts
        words = re.findall(r"[A-Za-z]{10,}", text)
        for w in words[:15]:
            for shift in range(1, 26):
                rotated = rot_decode(w, shift)
                for f in FLAG_PATTERN.findall(rotated):
                    found_flags.append(f)
                    self.log_action(f"Solved Caesar/ROT (Shift {shift}) flag: `{f}`")

        # 6. Single-Byte XOR on raw byte strings
        for line in text.splitlines():
            line_bytes = line.strip().encode("utf-8")
            if len(line_bytes) >= 8:
                xor_res = single_byte_xor_search(line_bytes)
                for key, flag in xor_res:
                    found_flags.append(flag)
                    self.log_action(f"Cracked single-byte XOR (Key 0x{key:02X}) -> `{flag}`")

        return list(set(found_flags))

    def attempt_reverse_engineering(self, text: str) -> List[str]:
        """Analyzes byte arrays, ordinal constants, and ASCII mappings."""
        flags = []
        # Hex array e.g. [0x46, 0x4C, 0x41, 0x47, 0x7B...]
        hex_arrays = re.findall(r"\[\s*(0x[0-9a-fA-F]{2}(?:\s*,\s*0x[0-9a-fA-F]{2})+)\s*\]", text)
        if hex_arrays:
            self.log_action("Parsed and decoded source code hex byte arrays")
            for arr in hex_arrays:
                try:
                    bytes_list = [int(h.strip(), 16) for h in arr.split(",")]
                    decoded_str = "".join([chr(b) if 32 <= b <= 126 else "." for b in bytes_list])
                    for f in FLAG_PATTERN.findall(decoded_str):
                        flags.append(f)
                        self.log_action(f"Decoded hex array constant: `{f}`")
                except Exception:
                    pass

        # Integer array e.g. [70, 76, 65, 71, 123...]
        int_arrays = re.findall(r"\[\s*([0-9]{2,3}(?:\s*,\s*[0-9]{2,3})+)\s*\]", text)
        for arr in int_arrays:
            try:
                ints = [int(x.strip()) for x in arr.split(",")]
                if all(32 <= x <= 126 for x in ints):
                    decoded_str = "".join(chr(x) for x in ints)
                    for f in FLAG_PATTERN.findall(decoded_str):
                        flags.append(f)
                        self.log_action(f"Decoded ASCII integer array: `{f}`")
            except Exception:
                pass

        return flags
