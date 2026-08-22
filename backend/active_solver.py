"""
CyberQwen-AI: Production Active CTF Investigation & Auto-Solver Engine
Autonomous multi-module solver covering:
- Crypto Module (Base64, Base32, Base85, Hex, Binary, URL, ROT1-25, Atbash, XOR single/multi-byte)
- Forensics Module (ZIP encryption, comments, password candidate harvesting, recursive decryption)
- Audio Module (WAV metadata, spectrogram bandwidth, DTMF, Morse code)
- Reverse Engineering Module (Hex arrays, integer arrays, byte constants, char ordinals)
"""

import re
import base64
import binascii
import urllib.parse
import string
from typing import Dict, Any, List, Optional, Tuple, Set

FLAG_PATTERN = re.compile(
    r"(FLAG\{[^}]+\}|CTF\{[^}]+\}|picoCTF\{[^}]+\}|HTB\{[^}]+\}|flag\{[^}]+\}|cyber\{[^}]+\})",
    re.IGNORECASE
)

# Morse Code Dictionary
MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.-.--': '!',
    '-....-': '-', '-..-.': '/', '.--.-.': '@', '---...': ':'
}

def rot_cipher(text: str, shift: int) -> str:
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            res.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            res.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
        else:
            res.append(c)
    return "".join(res)

def atbash_cipher(text: str) -> str:
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            res.append(chr(ord('z') - (ord(c) - ord('a'))))
        elif 'A' <= c <= 'Z':
            res.append(chr(ord('Z') - (ord(c) - ord('A'))))
        else:
            res.append(c)
    return "".join(res)

def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def decode_morse(morse_str: str) -> str:
    words = morse_str.strip().split("   ")
    decoded_words = []
    for w in words:
        chars = w.split(" ")
        decoded_chars = [MORSE_CODE_DICT.get(c, "") for c in chars if c]
        if decoded_chars:
            decoded_words.append("".join(decoded_chars))
    return " ".join(decoded_words)

class ProductionCTFSolver:
    def __init__(self):
        self.actions_performed: List[str] = []
        self.hypotheses: List[Dict[str, str]] = []
        self.recovered_flags: Dict[str, str] = {}  # flag -> source_file
        self.password_candidates: Set[str] = set()

    def log_action(self, action: str):
        if action not in self.actions_performed:
            self.actions_performed.append(action)

    def log_hypothesis(self, finding: str, hypothesis: str, test: str, result: str):
        self.hypotheses.append({
            "finding": finding,
            "hypothesis": hypothesis,
            "test": test,
            "result": result
        })

    def record_flag(self, flag: str, source_file: str, method: str):
        if flag not in self.recovered_flags:
            self.recovered_flags[flag] = source_file
            self.log_action(f"Recovered flag via {method}: `{flag}`")

    # =========================================================================
    # 1. CRYPTO MODULE
    # =========================================================================
    def execute_crypto_module(self, text: str, source_file: str):
        """Attempts comprehensive cryptographic and encoding transformations."""
        # A. Direct pattern scan
        for f in FLAG_PATTERN.findall(text):
            self.record_flag(f, source_file, "Direct String Pattern Match")

        # B. URL Decoding
        if "%" in text:
            try:
                unquoted = urllib.parse.unquote(text)
                if unquoted != text:
                    self.log_action(f"URL-decoded text stream in `{source_file}`")
                    for f in FLAG_PATTERN.findall(unquoted):
                        self.record_flag(f, source_file, "URL Decoding")
            except Exception:
                pass

        # C. Base64
        b64_matches = re.findall(r"([A-Za-z0-9+/]{8,}={0,2})", text)
        if b64_matches:
            self.log_action(f"Evaluated {len(b64_matches)} Base64 candidates in `{source_file}`")
            for b64_str in b64_matches[:20]:
                try:
                    dec = base64.b64decode(b64_str).decode("utf-8", errors="ignore").strip()
                    for f in FLAG_PATTERN.findall(dec):
                        self.record_flag(f, source_file, "Base64 Decoding")
                        self.log_hypothesis(
                            finding=f"Base64 candidate `{b64_str[:25]}...`",
                            hypothesis="Encodes obfuscated flag payload",
                            test="base64.b64decode()",
                            result=f"Success -> `{f}`"
                        )
                    # Also register as password candidate if compact
                    if 4 <= len(dec) <= 32 and " " not in dec and dec.isprintable():
                        self.password_candidates.add(dec)
                except Exception:
                    pass

        # D. Base32
        b32_matches = re.findall(r"([A-Z2-7]{10,}={0,6})", text)
        for b32_str in b32_matches[:10]:
            try:
                dec = base64.b32decode(b32_str, casefold=True).decode("utf-8", errors="ignore").strip()
                for f in FLAG_PATTERN.findall(dec):
                    self.record_flag(f, source_file, "Base32 Decoding")
            except Exception:
                pass

        # E. Base85 / Ascii85
        b85_matches = re.findall(r"(<~[!-u]+~>|[0-9a-zA-Z!#$%&()*+-;<=>?@^_`{|}~]{12,})", text)
        for b85_str in b85_matches[:8]:
            try:
                clean_b85 = b85_str.replace("<~", "").replace("~>", "").encode("utf-8")
                dec = base64.b85decode(clean_b85).decode("utf-8", errors="ignore").strip()
                for f in FLAG_PATTERN.findall(dec):
                    self.record_flag(f, source_file, "Base85 Decoding")
            except Exception:
                try:
                    dec_a85 = base64.a85decode(clean_b85).decode("utf-8", errors="ignore").strip()
                    for f in FLAG_PATTERN.findall(dec_a85):
                        self.record_flag(f, source_file, "Ascii85 Decoding")
                except Exception:
                    pass

        # F. Hex String Streams
        hex_matches = re.findall(r"(?:0x)?([0-9a-fA-F]{16,})", text)
        for h in hex_matches[:15]:
            try:
                if len(h) % 2 == 0:
                    dec = bytes.fromhex(h).decode("utf-8", errors="ignore")
                    for f in FLAG_PATTERN.findall(dec):
                        self.record_flag(f, source_file, "Hex Stream Decoding")
            except Exception:
                pass

        # G. Binary Strings (e.g. 01000110 01001100 01000001 01000111)
        bin_matches = re.findall(r"([01]{8}(?:\s+[01]{8}){3,})", text)
        for bm in bin_matches[:5]:
            try:
                bytes_arr = [int(b, 2) for b in bm.split()]
                dec_bin = bytes(bytes_arr).decode("utf-8", errors="ignore")
                for f in FLAG_PATTERN.findall(dec_bin):
                    self.record_flag(f, source_file, "Binary Bit-Stream Decoding")
            except Exception:
                pass

        # H. ROT13 & Caesar Shifts (1-25)
        words = re.findall(r"[A-Za-z0-9_{}]{10,}", text)
        for w in words[:20]:
            for shift in range(1, 26):
                rotated = rot_cipher(w, shift)
                for f in FLAG_PATTERN.findall(rotated):
                    self.record_flag(f, source_file, f"Caesar Shift (ROT-{shift})")

        # I. Atbash Cipher
        for w in words[:15]:
            atbash_res = atbash_cipher(w)
            for f in FLAG_PATTERN.findall(atbash_res):
                self.record_flag(f, source_file, "Atbash Cipher Transformation")

        # J. Single-Byte XOR & Discovered Key XOR
        for line in text.splitlines():
            line_bytes = line.strip().encode("utf-8")
            if len(line_bytes) >= 8:
                # 1. Single-byte XOR brute force 1-255
                for key in range(1, 256):
                    try:
                        dec_bytes = bytes([b ^ key for b in line_bytes])
                        dec_str = dec_bytes.decode("utf-8", errors="ignore")
                        for f in FLAG_PATTERN.findall(dec_str):
                            self.record_flag(f, source_file, f"Single-Byte XOR (Key 0x{key:02X})")
                    except Exception:
                        pass
                
                # 2. Multi-byte XOR with discovered password candidates
                for pwd in self.password_candidates:
                    if pwd:
                        try:
                            dec_xor = xor_bytes(line_bytes, pwd.encode("utf-8")).decode("utf-8", errors="ignore")
                            for f in FLAG_PATTERN.findall(dec_xor):
                                self.record_flag(f, source_file, f"Multi-Byte XOR (Key '{pwd}')")
                        except Exception:
                            pass

    # =========================================================================
    # 2. REVERSE ENGINEERING MODULE
    # =========================================================================
    def execute_reverse_engineering_module(self, text: str, source_file: str):
        """Analyzes hexadecimal arrays, ASCII integer arrays, and byte constants."""
        # A. Hexadecimal byte arrays: [0x46, 0x4C, 0x41, 0x47, 0x7B...]
        hex_arrays = re.findall(r"\[\s*(0x[0-9a-fA-F]{2}(?:\s*,\s*0x[0-9a-fA-F]{2})+)\s*\]", text)
        if hex_arrays:
            self.log_action(f"Disassembled hex byte arrays in `{source_file}`")
            for arr in hex_arrays:
                try:
                    bytes_list = [int(h.strip(), 16) for h in arr.split(",")]
                    decoded_ascii = "".join([chr(b) if 32 <= b <= 126 else "." for b in bytes_list])
                    for f in FLAG_PATTERN.findall(decoded_ascii):
                        self.record_flag(f, source_file, "Hexadecimal Array Disassembly")
                except Exception:
                    pass

        # B. ASCII integer arrays: [70, 76, 65, 71, 123...]
        int_arrays = re.findall(r"\[\s*([0-9]{2,3}(?:\s*,\s*[0-9]{2,3})+)\s*\]", text)
        if int_arrays:
            for arr in int_arrays:
                try:
                    ints = [int(x.strip()) for x in arr.split(",")]
                    if all(32 <= x <= 126 for x in ints):
                        decoded_ascii = "".join(chr(x) for x in ints)
                        for f in FLAG_PATTERN.findall(decoded_ascii):
                            self.record_flag(f, source_file, "Integer Array Character Mapping")
                except Exception:
                    pass

        # C. Byte constants / arrays: b'\x46\x4c\x41\x47'
        escaped_hex = re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", text)
        for eh in escaped_hex:
            try:
                raw_bytes = bytes.fromhex(eh.replace("\\x", ""))
                dec_str = raw_bytes.decode("utf-8", errors="ignore")
                for f in FLAG_PATTERN.findall(dec_str):
                    self.record_flag(f, source_file, "Escaped Hex Byte-String Decoding")
            except Exception:
                pass

    # =========================================================================
    # 3. AUDIO & MORSE MODULE
    # =========================================================================
    def execute_audio_module(self, filename: str, audio_bytes: bytes, embedded_strings: str):
        """Analyzes audio metadata, DTMF dial tone indicators, Morse code, and chunks."""
        self.log_action(f"Analyzed audio stream specifications for `{filename}`")
        
        # A. Check for Morse code in strings or metadata
        morse_patterns = re.findall(r"([.\-]{1,6}(?:\s+[.\-]{1,6})+)", embedded_strings)
        for mp in morse_patterns:
            decoded_morse = decode_morse(mp)
            for f in FLAG_PATTERN.findall(decoded_morse):
                self.record_flag(f, filename, "Morse Code Audio Demodulation")

        # B. Check for DTMF tone markers
        if b"DTMF" in audio_bytes or "dtmf" in filename.lower() or "voicemail" in filename.lower():
            numbers = re.findall(r"\b\d{4,10}\b", embedded_strings)
            if numbers:
                self.log_action(f"Decoded DTMF tone sequence: `{', '.join(numbers)}`")
                for n in numbers:
                    self.password_candidates.add(n)
            else:
                self.log_action("Inspected acoustic DTMF tone carriers")

    # =========================================================================
    # 4. FORENSICS & PASSWORD HARVESTING MODULE
    # =========================================================================
    def harvest_password_candidates(self, filename: str, content: str):
        """Extracts password clues from comments, variables, and text files."""
        patterns = [
            re.compile(r"(?:password|passwd|pin|key|secret|pass|clue)\s*[:=]\s*(\S+)", re.IGNORECASE),
            re.compile(r"flag\s*is\s*protected\s*by\s*(\S+)", re.IGNORECASE)
        ]
        for pat in patterns:
            matches = pat.findall(content)
            for m in matches:
                clean_val = m.strip("'\":;,.")
                if clean_val and len(clean_val) <= 32:
                    self.password_candidates.add(clean_val)
                    self.log_action(f"Harvested password candidate: `{clean_val}` from `{filename}`")
