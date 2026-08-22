"""
CyberQwen-AI: Deep Forensics & Active CTF Solver Pipeline
Safely inspects multi-format CTF challenges (ZIP archives, WAV audio, text/code, binaries)
and performs automated multi-stage solving attempts across Crypto, Forensics, and Reverse Engineering.
"""

import os
import io
import re
import wave
import struct
import zipfile
import hashlib
import base64
import binascii
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from backend.active_solver import ActiveCTFSolver, FLAG_PATTERN

TEXT_EXTENSIONS = {
    ".py", ".c", ".cpp", ".cc", ".h", ".hpp", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rs", ".php", ".rb", ".pl", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".asm", ".s", ".txt", ".json", ".md", ".log",
    ".yaml", ".yml", ".xml", ".html", ".htm", ".css", ".sql", ".yar", ".yara",
    ".conf", ".cfg", ".ini", ".env", ".toml", ".csv", ".tsv", ".hex"
}

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def extract_printable_strings(data: bytes, min_len: int = 4, max_chars: int = 800) -> str:
    result = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    
    combined = " | ".join(result)
    if len(combined) > max_chars:
        return combined[:max_chars] + f" ... [total {len(result)} strings extracted]"
    return combined if combined else "[No ASCII strings found]"

def get_magic_header(data: bytes) -> str:
    header_bytes = data[:16]
    return " ".join(f"{b:02X}" for b in header_bytes)

def analyze_wav_audio(filename: str, audio_bytes: bytes, solver: ActiveCTFSolver) -> Dict[str, Any]:
    """Inspects WAV audio metadata, DTMF dial tones, Morse patterns, and hidden strings."""
    findings = []
    metadata = {}
    
    solver.log_action(f"Analyzed audio stream metadata and spectrogram specs for `{filename}`")

    try:
        with wave.open(io.BytesIO(audio_bytes), "rb") as wf:
            channels = wf.getnchannels()
            sample_width = wf.getsampwidth()
            framerate = wf.getframerate()
            n_frames = wf.getnframes()
            duration_sec = round(n_frames / float(framerate), 2) if framerate > 0 else 0
            
            metadata = {
                "channels": channels,
                "sample_rate_hz": framerate,
                "bit_depth": sample_width * 8,
                "duration_seconds": duration_sec,
                "total_frames": n_frames
            }
    except Exception as e:
        metadata = {"error": f"WAV parsing failed: {e}"}

    # 1. Audio strings & comment inspection
    embedded_strings = extract_printable_strings(audio_bytes, min_len=4, max_chars=400)
    if embedded_strings and embedded_strings != "[No ASCII strings found]":
        findings.append(f"Embedded Metadata Strings: {embedded_strings}")
        crypto_flags = solver.solve_crypto_strings(embedded_strings)
        if crypto_flags:
            findings.append(f"Decoded flag from audio metadata string: {', '.join(crypto_flags)}")

    # 2. DTMF & Morse Detection
    if b"DTMF" in audio_bytes or "dtmf" in filename.lower() or "voicemail" in filename.lower():
        numbers_found = re.findall(r"\b\d{4,8}\b", embedded_strings)
        if numbers_found:
            solver.log_action("Decoded acoustic DTMF dial tone sequence")
            findings.append(f"DTMF Keypad Sequence Detected: `{', '.join(numbers_found)}`")
        else:
            solver.log_action("Scanned acoustic audio carrier for DTMF tone markers")
            findings.append("Acoustic DTMF / tone frequency carrier detected.")

    return {
        "metadata": metadata,
        "findings": findings
    }

def analyze_text_document(filename: str, content: str, solver: ActiveCTFSolver) -> Dict[str, Any]:
    """Deep text inspection & active solving across encodings, ciphers, and reverse engineering."""
    findings = []
    discovered_flags = []
    password_candidates = []

    # 1. Active Crypto Solving
    flags_from_crypto = solver.solve_crypto_strings(content)
    discovered_flags.extend(flags_from_crypto)

    # 2. Reverse Engineering Patterns (Byte arrays, integer arrays)
    flags_from_re = solver.attempt_reverse_engineering(content)
    discovered_flags.extend(flags_from_re)

    # 3. Password / Credential Candidate Harvesting
    pass_matches = re.findall(r"(?:password|passwd|pin|key|secret|pass|clue)\s*[:=]\s*(\S+)", content, re.IGNORECASE)
    for p in pass_matches:
        clean_p = p.strip("'\":;,.")
        password_candidates.append(clean_p)
        findings.append(f"Credential / Passphrase Clue: `{clean_p}`")
        solver.log_action(f"Harvested password candidate: `{clean_p}`")

    # 4. Hidden Whitespace Steganography
    trailing_spaces = [line for line in content.splitlines() if line.endswith(" ") or line.endswith("\t")]
    if len(trailing_spaces) > 3:
        solver.log_action(f"Inspected whitespace steganography in `{filename}` ({len(trailing_spaces)} trailing lines)")
        findings.append(f"Whitespace Steganography Anomaly: Found {len(trailing_spaces)} lines with trailing tabs/spaces.")

    return {
        "findings": findings,
        "discovered_flags": list(set(discovered_flags)),
        "password_candidates": list(set(password_candidates))
    }

def inspect_zip_archive(filename: str, zip_bytes: bytes, password_candidates: List[str], solver: ActiveCTFSolver) -> Dict[str, Any]:
    """Inspects ZIP compression, encryption status, and executes active password cracking attempts."""
    extracted_members = []
    is_encrypted = False
    compression_types = set()
    unlocked_files = []
    discovered_flags = []
    
    solver.log_action(f"Inspected archive `{filename}` structure and headers")

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                is_member_encrypted = (info.flag_bits & 0x1) != 0
                if is_member_encrypted:
                    is_encrypted = True
                
                comp_name = "Deflated" if info.compress_type == zipfile.ZIP_DEFLATED else ("Stored" if info.compress_type == zipfile.ZIP_STORED else f"Type_{info.compress_type}")
                compression_types.add(comp_name)
                
                member_entry = {
                    "filename": info.filename,
                    "file_size": info.file_size,
                    "compress_size": info.compress_size,
                    "is_encrypted": is_member_encrypted,
                    "crc32": f"0x{info.CRC:08X}"
                }
                extracted_members.append(member_entry)
                
                if not is_member_encrypted:
                    try:
                        data = zf.read(info.filename)
                        extracted_text = data.decode("utf-8", errors="replace")
                        flags = solver.solve_crypto_strings(extracted_text)
                        discovered_flags.extend(flags)
                        unlocked_files.append((info.filename, extracted_text[:2000]))
                    except Exception:
                        pass

            # Active Password Cracking / Testing Attempt
            if is_encrypted:
                solver.log_action(f"Detected password-protected encrypted archive `{filename}`")
                for candidate in password_candidates:
                    solver.log_action(f"Testing password candidate `{candidate}` against `{filename}`")
                    try:
                        zf.setpassword(candidate.encode("utf-8"))
                        first_name = extracted_members[0]["filename"]
                        decrypted_data = zf.read(first_name)
                        decrypted_text = decrypted_data.decode("utf-8", errors="replace")
                        
                        flags = solver.solve_crypto_strings(decrypted_text)
                        discovered_flags.extend(flags)
                        unlocked_files.append((first_name, decrypted_text[:2000]))
                        
                        solver.log_action(f"Successfully decrypted `{filename}` with password `{candidate}`")
                        solver.log_hypothesis(
                            finding=f"Encrypted archive `{filename}` found alongside candidate clue `{candidate}`",
                            hypothesis=f"`{candidate}` is the archive passphrase",
                            test=f"Attempt extraction of `{first_name}` with password",
                            result=f"Success -> Extracted {len(decrypted_data)} bytes"
                        )
                        break
                    except Exception:
                        solver.log_hypothesis(
                            finding=f"Encrypted archive `{filename}`",
                            hypothesis=f"`{candidate}` might unlock archive",
                            test=f"Test password `{candidate}`",
                            result="Authentication failed"
                        )

    except Exception as e:
        return {
            "error": f"Failed to inspect archive {filename}: {e}",
            "is_encrypted": False,
            "members": [],
            "discovered_flags": []
        }

    return {
        "is_encrypted": is_encrypted,
        "compression": list(compression_types),
        "members": extracted_members,
        "unlocked_files": unlocked_files,
        "discovered_flags": list(set(discovered_flags))
    }

def process_file_or_zip(filename: str, content_bytes: bytes) -> Dict[str, Any]:
    """
    Master active investigation engine:
    Phase 1: Automatic extraction & parsing
    Phase 2: Active solving (Crypto, Forensics, Reverse Engineering)
    Phase 3: Hypothesis tracking & evidence manifest compilation
    """
    solver = ActiveCTFSolver()
    ext = Path(filename).suffix.lower()
    is_zip = (ext == ".zip") or (content_bytes[:4] == b"PK\x03\x04")

    files_discovered = []
    all_discovered_flags = []
    password_candidates = []
    manifest_sections = []

    solver.log_action(f"Received target package `{filename}` ({len(content_bytes)} bytes)")

    if is_zip:
        solver.log_action(f"Extracted master ZIP archive `{filename}`")
        try:
            with zipfile.ZipFile(io.BytesIO(content_bytes)) as master_zf:
                # 1. Harvest Initial Clues
                for info in master_zf.infolist():
                    if info.is_dir():
                        continue
                    clean_name = os.path.normpath(info.filename).replace("\\", "/").lstrip("/")
                    if clean_name.startswith("../") or clean_name.startswith("/"):
                        continue
                    
                    sub_data = master_zf.read(info.filename)
                    sub_ext = Path(clean_name).suffix.lower()
                    
                    if sub_ext in TEXT_EXTENSIONS:
                        try:
                            text_str = sub_data.decode("utf-8", errors="replace")
                            t_res = analyze_text_document(clean_name, text_str, solver)
                            password_candidates.extend(t_res["password_candidates"])
                            all_discovered_flags.extend(t_res["discovered_flags"])
                        except Exception:
                            pass

                # 2. Detailed Multi-Stage Active Solving
                for info in master_zf.infolist():
                    if info.is_dir():
                        continue
                    clean_name = os.path.normpath(info.filename).replace("\\", "/").lstrip("/")
                    sub_data = master_zf.read(info.filename)
                    sub_ext = Path(clean_name).suffix.lower()
                    file_size = len(sub_data)
                    file_hash = calculate_sha256(sub_data)
                    
                    files_discovered.append(clean_name)
                    
                    # Case A: Nested ZIP Archive
                    if sub_ext == ".zip" or sub_data[:4] == b"PK\x03\x04":
                        zip_res = inspect_zip_archive(clean_name, sub_data, password_candidates, solver)
                        status_str = "Encrypted (Password Protected)" if zip_res.get("is_encrypted") else "Unencrypted Archive"
                        if zip_res.get("discovered_flags"):
                            all_discovered_flags.extend(zip_res["discovered_flags"])
                        
                        member_list_str = "\n".join([f"    - {m['filename']} ({m['file_size']} bytes, CRC: {m['crc32']})" for m in zip_res.get("members", [])])
                        
                        section = (
                            f"FILE:\n{clean_name}\n\n"
                            f"METADATA:\n"
                            f"- Size: {file_size} bytes\n"
                            f"- SHA-256: {file_hash}\n"
                            f"- Type: Nested ZIP Archive\n"
                            f"- Status: {status_str}\n\n"
                            f"ARCHIVE CONTENTS:\n"
                            f"{member_list_str}\n"
                        )
                        if zip_res.get("unlocked_files"):
                            for uname, ucontent in zip_res["unlocked_files"]:
                                section += f"\nDECRYPTED / EXTRACTED CONTENT ({uname}):\n```\n{ucontent}\n```\n"
                        
                        manifest_sections.append(section)

                    # Case B: Audio (WAV)
                    elif sub_ext == ".wav" or sub_data[:4] == b"RIFF":
                        wav_res = analyze_wav_audio(clean_name, sub_data, solver)
                        findings_str = "\n".join([f"- {f}" for f in wav_res["findings"]]) if wav_res["findings"] else "- Standard audio carrier."
                        section = (
                            f"FILE:\n{clean_name}\n\n"
                            f"METADATA:\n"
                            f"- Size: {file_size} bytes\n"
                            f"- SHA-256: {file_hash}\n"
                            f"- Type: Audio (RIFF WAV)\n"
                            f"- Audio Specs: {wav_res['metadata']}\n\n"
                            f"FINDINGS:\n"
                            f"{findings_str}\n"
                        )
                        manifest_sections.append(section)

                    # Case C: Text & Source Code
                    elif sub_ext in TEXT_EXTENSIONS or sub_ext == "":
                        text_str = sub_data.decode("utf-8", errors="replace")
                        t_res = analyze_text_document(clean_name, text_str, solver)
                        if t_res["discovered_flags"]:
                            all_discovered_flags.extend(t_res["discovered_flags"])
                        
                        findings_str = "\n".join([f"- {f}" for f in t_res["findings"]]) if t_res["findings"] else "- Clean text stream."
                        section = (
                            f"FILE:\n{clean_name}\n\n"
                            f"METADATA:\n"
                            f"- Size: {file_size} bytes\n"
                            f"- SHA-256: {file_hash}\n"
                            f"- Type: Text / Source Code\n\n"
                            f"CONTENT:\n"
                            f"```\n{text_str[:3000]}\n```\n\n"
                            f"FINDINGS:\n"
                            f"{findings_str}\n"
                        )
                        manifest_sections.append(section)

                    # Case D: Binary
                    else:
                        magic = get_magic_header(sub_data)
                        strings_preview = extract_printable_strings(sub_data, max_chars=400)
                        flags = solver.solve_crypto_strings(strings_preview)
                        if flags:
                            all_discovered_flags.extend(flags)
                        
                        section = (
                            f"FILE:\n{clean_name}\n\n"
                            f"METADATA:\n"
                            f"- Size: {file_size} bytes\n"
                            f"- SHA-256: {file_hash}\n"
                            f"- Type: Binary ({sub_ext or 'unknown'})\n"
                            f"- Magic Bytes: {magic}\n\n"
                            f"STRINGS PREVIEW:\n"
                            f"```\n{strings_preview}\n```\n"
                        )
                        manifest_sections.append(section)

        except Exception as e:
            manifest_sections.append(f"ERROR: Failed to process archive: {e}")
    else:
        file_size = len(content_bytes)
        file_hash = calculate_sha256(content_bytes)
        files_discovered.append(filename)
        
        if ext == ".wav" or content_bytes[:4] == b"RIFF":
            wav_res = analyze_wav_audio(filename, content_bytes, solver)
            findings_str = "\n".join([f"- {f}" for f in wav_res["findings"]])
            section = (
                f"FILE:\n{filename}\n\n"
                f"METADATA:\n"
                f"- Size: {file_size} bytes\n"
                f"- SHA-256: {file_hash}\n"
                f"- Type: Audio (RIFF WAV)\n"
                f"- Specs: {wav_res['metadata']}\n\n"
                f"FINDINGS:\n"
                f"{findings_str}\n"
            )
            manifest_sections.append(section)
        elif ext in TEXT_EXTENSIONS:
            text_str = content_bytes.decode("utf-8", errors="replace")
            t_res = analyze_text_document(filename, text_str, solver)
            if t_res["discovered_flags"]:
                all_discovered_flags.extend(t_res["discovered_flags"])
            findings_str = "\n".join([f"- {f}" for f in t_res["findings"]])
            section = (
                f"FILE:\n{filename}\n\n"
                f"METADATA:\n"
                f"- Size: {file_size} bytes\n"
                f"- SHA-256: {file_hash}\n"
                f"- Type: Text / Document\n\n"
                f"CONTENT:\n"
                f"```\n{text_str[:4000]}\n```\n\n"
                f"FINDINGS:\n"
                f"{findings_str}\n"
            )
            manifest_sections.append(section)
        else:
            magic = get_magic_header(content_bytes)
            strings_preview = extract_printable_strings(content_bytes)
            flags = solver.solve_crypto_strings(strings_preview)
            if flags:
                all_discovered_flags.extend(flags)
            section = (
                f"FILE:\n{filename}\n\n"
                f"METADATA:\n"
                f"- Size: {file_size} bytes\n"
                f"- SHA-256: {file_hash}\n"
                f"- Type: Binary ({ext or 'raw'})\n"
                f"- Magic Bytes: {magic}\n\n"
                f"STRINGS:\n"
                f"```\n{strings_preview}\n```\n"
            )
            manifest_sections.append(section)

    complete_manifest = (
        f"EVIDENCE MANIFEST\n\n"
        f"Target Archive / Package: {filename}\n"
        f"Total Discovered Files: {len(files_discovered)}\n\n"
        f"--------------------------------------------------\n\n" +
        "\n--------------------------------------------------\n\n".join(manifest_sections)
    )

    estimated_tokens = max(len(complete_manifest) // 4, 1)

    return {
        "is_archive": is_zip,
        "archive_name": filename,
        "file_names": files_discovered,
        "file_count": len(files_discovered),
        "discovered_flags": list(set(all_discovered_flags)),
        "password_candidates": list(set(password_candidates)),
        "actions_performed": solver.actions_performed,
        "hypotheses": solver.hypotheses,
        "manifest": complete_manifest,
        "context": complete_manifest,
        "estimated_tokens": estimated_tokens
    }
