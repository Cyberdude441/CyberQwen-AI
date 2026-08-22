"""
CyberQwen-AI: Production Archive Processor & Forensic Auto-Solver Pipeline
Coordinates Phase 1 (File Triage & Extraction) and Phase 2 (Automated Solving Engine)
with full recursive decryption of nested archives.
"""

import os
import io
import re
import wave
import struct
import zipfile
import hashlib
import base64
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from backend.active_solver import ProductionCTFSolver, FLAG_PATTERN

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

def analyze_wav_audio(filename: str, audio_bytes: bytes, solver: ProductionCTFSolver) -> Dict[str, Any]:
    """Inspects WAV audio metadata, DTMF dial tones, Morse patterns, and hidden strings."""
    findings = []
    metadata = {}
    
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
        metadata = {"error": f"WAV header error: {e}"}

    embedded_strings = extract_printable_strings(audio_bytes, min_len=4, max_chars=400)
    solver.execute_audio_module(filename, audio_bytes, embedded_strings)
    solver.execute_crypto_module(embedded_strings, filename)

    if embedded_strings and embedded_strings != "[No ASCII strings found]":
        findings.append(f"Embedded Metadata Strings: {embedded_strings}")

    return {
        "metadata": metadata,
        "findings": findings
    }

def analyze_text_document(filename: str, content: str, solver: ProductionCTFSolver) -> Dict[str, Any]:
    """Deep text inspection & active solving across encodings, ciphers, and reverse engineering."""
    findings = []

    # 1. Harvest Password Clues
    solver.harvest_password_candidates(filename, content)

    # 2. Run Crypto Module
    solver.execute_crypto_module(content, filename)

    # 3. Run Reverse Engineering Module
    solver.execute_reverse_engineering_module(content, filename)

    # 4. Hidden Whitespace Steganography
    trailing_spaces = [line for line in content.splitlines() if line.endswith(" ") or line.endswith("\t")]
    if len(trailing_spaces) > 3:
        solver.log_action(f"Inspected whitespace steganography in `{filename}`")
        findings.append(f"Whitespace Steganography Anomaly: Found {len(trailing_spaces)} lines with trailing tabs/spaces.")

    return {
        "findings": findings
    }

def inspect_and_crack_zip(
    filename: str,
    zip_bytes: bytes,
    solver: ProductionCTFSolver
) -> Dict[str, Any]:
    """Inspects ZIP compression, detects encryption, and tests password candidates."""
    extracted_members = []
    is_encrypted = False
    compression_types = set()
    unlocked_files = []
    
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
                
                # If unencrypted, read content and solve
                if not is_member_encrypted:
                    try:
                        data = zf.read(info.filename)
                        extracted_text = data.decode("utf-8", errors="replace")
                        solver.execute_crypto_module(extracted_text, f"{filename}/{info.filename}")
                        solver.execute_reverse_engineering_module(extracted_text, f"{filename}/{info.filename}")
                        unlocked_files.append((info.filename, extracted_text[:2000]))
                    except Exception:
                        pass

            # Active Password Cracking / Testing
            if is_encrypted:
                solver.log_action(f"Detected encryption in `{filename}`")
                solver.log_action("Generated password candidates from harvested clues")
                
                for candidate in list(solver.password_candidates):
                    solver.log_action(f"Tested password candidate `{candidate}` against `{filename}`")
                    try:
                        zf.setpassword(candidate.encode("utf-8"))
                        first_name = extracted_members[0]["filename"]
                        decrypted_data = zf.read(first_name)
                        decrypted_text = decrypted_data.decode("utf-8", errors="replace")
                        
                        # Solve against decrypted payload
                        solver.execute_crypto_module(decrypted_text, f"{filename}/{first_name}")
                        solver.execute_reverse_engineering_module(decrypted_text, f"{filename}/{first_name}")
                        unlocked_files.append((first_name, decrypted_text[:2000]))
                        
                        solver.log_action(f"Decoded hidden content from `{filename}` with password `{candidate}`")
                        solver.log_hypothesis(
                            finding=f"Encrypted archive `{filename}` found alongside clue `{candidate}`",
                            hypothesis=f"`{candidate}` is the archive passphrase",
                            test=f"Attempt extraction of `{first_name}` with password",
                            result=f"Success -> Decrypted {len(decrypted_data)} bytes"
                        )
                        break
                    except Exception:
                        pass

    except Exception as e:
        return {
            "error": f"Failed to inspect archive {filename}: {e}",
            "is_encrypted": False,
            "members": [],
            "unlocked_files": []
        }

    return {
        "is_encrypted": is_encrypted,
        "compression": list(compression_types),
        "members": extracted_members,
        "unlocked_files": unlocked_files
    }

def process_file_or_zip(filename: str, content_bytes: bytes) -> Dict[str, Any]:
    """
    Master active investigation engine:
    Phase 1: File Triage & Extraction
    Phase 2: Automated Multi-Module Solving Engine (Crypto, Forensics, Audio, Reverse Engineering)
    """
    solver = ProductionCTFSolver()
    ext = Path(filename).suffix.lower()
    is_zip = (ext == ".zip") or (content_bytes[:4] == b"PK\x03\x04")

    files_discovered = []
    manifest_sections = []

    solver.log_action(f"Received target package `{filename}` ({len(content_bytes)} bytes)")

    if is_zip:
        solver.log_action(f"Extracted master ZIP archive `{filename}`")
        try:
            with zipfile.ZipFile(io.BytesIO(content_bytes)) as master_zf:
                # Pass 1: Harvest initial text clues & password candidates across all files
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
                            analyze_text_document(clean_name, text_str, solver)
                        except Exception:
                            pass

                # Pass 2: Comprehensive deep inspection & solving
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
                        zip_res = inspect_and_crack_zip(clean_name, sub_data, solver)
                        status_str = "Encrypted (Password Protected)" if zip_res.get("is_encrypted") else "Unencrypted Archive"
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
                            f"- Specs: {wav_res['metadata']}\n\n"
                            f"FINDINGS:\n"
                            f"{findings_str}\n"
                        )
                        manifest_sections.append(section)

                    # Case C: Text & Source Code
                    elif sub_ext in TEXT_EXTENSIONS or sub_ext == "":
                        text_str = sub_data.decode("utf-8", errors="replace")
                        t_res = analyze_text_document(clean_name, text_str, solver)
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
                        solver.execute_crypto_module(strings_preview, clean_name)
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
            solver.execute_crypto_module(strings_preview, filename)
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
        "recovered_flags": solver.recovered_flags,
        "discovered_flags": list(solver.recovered_flags.keys()),
        "password_candidates": list(solver.password_candidates),
        "actions_performed": solver.actions_performed,
        "hypotheses": solver.hypotheses,
        "manifest": complete_manifest,
        "context": complete_manifest,
        "estimated_tokens": estimated_tokens
    }
