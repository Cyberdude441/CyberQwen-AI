"""
CyberQwen-AI: Archive & Multi-File Forensics Processor
Safely extracts and parses ZIP archives, source code files, logs, and binary metadata
into structured analysis context without executing any target files.
"""

import os
import io
import re
import zipfile
import hashlib
import base64
from pathlib import Path
from typing import Dict, Any, List, Optional

TEXT_EXTENSIONS = {
    ".py", ".c", ".cpp", ".cc", ".h", ".hpp", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rs", ".php", ".rb", ".pl", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".asm", ".s", ".txt", ".json", ".md", ".log",
    ".yaml", ".yml", ".xml", ".html", ".htm", ".css", ".sql", ".yar", ".yara",
    ".conf", ".cfg", ".ini", ".env", ".toml", ".csv", ".tsv", ".hex"
}

FLAG_REGEX = re.compile(r"(FLAG\{[^}]+\}|CTF\{[^}]+\}|picoCTF\{[^}]+\}|HTB\{[^}]+\}|flag\{[^}]+\}|cyber\{[^}]+\})", re.IGNORECASE)
BASE64_REGEX = re.compile(r"([A-Za-z0-9+/]{12,}={0,2})")
HEX_ARRAY_REGEX = re.compile(r"(0x[0-9a-fA-F]{2},\s*)+0x[0-9a-fA-F]{2}")

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def extract_printable_strings(data: bytes, min_len: int = 4, max_chars: int = 600) -> str:
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
        return combined[:max_chars] + f" ... [truncated, total {len(result)} strings]"
    return combined if combined else "[No ASCII strings found]"

def get_magic_header(data: bytes) -> str:
    header_bytes = data[:16]
    return " ".join(f"{b:02X}" for b in header_bytes)

def scan_for_artifacts(text: str) -> Dict[str, List[str]]:
    findings = {
        "flags": [],
        "base64_decoded": [],
        "hex_decoded": [],
        "urls": [],
        "secrets": []
    }

    # 1. Direct Flag Pattern
    flags_found = FLAG_REGEX.findall(text)
    if flags_found:
        findings["flags"] = list(set(flags_found))

    # 2. Base64 Detection & Decoding
    b64_matches = BASE64_REGEX.findall(text)
    for b64_str in b64_matches[:10]:
        try:
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore").strip()
            if len(decoded) >= 4 and any(c.isalnum() for c in decoded):
                if FLAG_REGEX.search(decoded):
                    findings["flags"].extend(FLAG_REGEX.findall(decoded))
                findings["base64_decoded"].append(f"`{b64_str[:30]}...` -> `{decoded[:100]}`")
        except Exception:
            pass

    # 3. Hex Byte Arrays
    for match in HEX_ARRAY_REGEX.finditer(text):
        raw_hex = match.group(0)
        try:
            bytes_list = [int(h.strip(), 16) for h in raw_hex.split(",")]
            decoded_ascii = "".join([chr(b) if 32 <= b <= 126 else "." for b in bytes_list])
            if FLAG_REGEX.search(decoded_ascii):
                findings["flags"].extend(FLAG_REGEX.findall(decoded_ascii))
            findings["hex_decoded"].append(f"{raw_hex[:40]}... -> `{decoded_ascii}`")
        except Exception:
            pass

    # 4. URLs
    urls = re.findall(r"https?://[^\s<>]+", text)
    if urls:
        findings["urls"] = list(set(urls))[:5]

    # 5. Secrets / Keywords
    secret_keywords = ["password", "passwd", "secret", "private_key", "flag", "token", "auth_key", "admin_pass"]
    for kw in secret_keywords:
        pattern = re.compile(rf"{kw}\s*[:=]\s*(\S+)", re.IGNORECASE)
        for m in pattern.findall(text):
            clean_val = m.strip("'\":;,")
            findings["secrets"].append(f"{kw}: `{clean_val}`")

    findings["flags"] = list(set(findings["flags"]))
    return findings

def process_file_or_zip(filename: str, content_bytes: bytes) -> Dict[str, Any]:
    ext = Path(filename).suffix.lower()
    is_zip = (ext == ".zip") or (content_bytes[:4] == b"PK\x03\x04")

    extracted_files: List[Dict[str, Any]] = []

    if is_zip:
        try:
            with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
                for member in zf.infolist():
                    if member.is_dir():
                        continue
                    clean_name = os.path.normpath(member.filename).replace("\\", "/").lstrip("/")
                    if clean_name.startswith("../") or clean_name.startswith("/"):
                        continue
                    
                    file_data = zf.read(member.filename)
                    sub_ext = Path(clean_name).suffix.lower()
                    file_hash = calculate_sha256(file_data)
                    file_size = len(file_data)
                    
                    if sub_ext in TEXT_EXTENSIONS or sub_ext == "":
                        try:
                            text_content = file_data.decode("utf-8")
                        except UnicodeDecodeError:
                            text_content = file_data.decode("latin-1", errors="replace")
                        file_type = "Text / Source Code"
                    elif sub_ext == ".pdf":
                        try:
                            import pypdf
                            reader = pypdf.PdfReader(io.BytesIO(file_data))
                            text_content = "\n".join([page.extract_text() or "" for page in reader.pages])
                            file_type = "PDF Document"
                        except Exception as e:
                            text_content = f"[PDF extraction failed: {e}]"
                            file_type = "PDF Document (Corrupted)"
                    else:
                        magic = get_magic_header(file_data)
                        strings_preview = extract_printable_strings(file_data)
                        text_content = f"[Binary File - Magic: {magic}]\nStrings Preview: {strings_preview}"
                        file_type = f"Binary ({sub_ext or 'unknown'})"

                    artifacts = scan_for_artifacts(text_content)

                    extracted_files.append({
                        "name": clean_name,
                        "size": file_size,
                        "hash": file_hash,
                        "type": file_type,
                        "content": text_content,
                        "artifacts": artifacts
                    })

        except Exception as e:
            extracted_files.append({
                "name": filename,
                "size": len(content_bytes),
                "hash": calculate_sha256(content_bytes),
                "type": "Corrupted ZIP / Raw Binary",
                "content": f"[Error reading ZIP: {e}]",
                "artifacts": {"flags": [], "base64_decoded": [], "hex_decoded": [], "urls": [], "secrets": []}
            })
    else:
        file_hash = calculate_sha256(content_bytes)
        file_size = len(content_bytes)

        if ext in TEXT_EXTENSIONS:
            try:
                text_content = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text_content = content_bytes.decode("latin-1", errors="replace")
            file_type = "Source Code / Text Document"
        elif ext == ".pdf":
            try:
                import pypdf
                reader = pypdf.PdfReader(io.BytesIO(content_bytes))
                text_content = "\n".join([page.extract_text() or "" for page in reader.pages])
                file_type = "PDF Document"
            except Exception as e:
                text_content = f"[PDF extraction failed: {e}]"
                file_type = "PDF Document (Corrupted)"
        else:
            magic = get_magic_header(content_bytes)
            strings_preview = extract_printable_strings(content_bytes)
            text_content = f"[Binary File - Magic: {magic}]\nStrings Preview: {strings_preview}"
            file_type = f"Binary ({ext or 'raw'})"

        artifacts = scan_for_artifacts(text_content)

        extracted_files.append({
            "name": filename,
            "size": file_size,
            "hash": file_hash,
            "type": file_type,
            "content": text_content,
            "artifacts": artifacts
        })

    all_discovered_flags = []
    evidence_findings = []
    context_blocks = []
    file_names_list = []

    for f_info in extracted_files:
        file_names_list.append(f_info["name"])
        content_snippet = f_info["content"]
        if len(content_snippet) > 3500:
            content_snippet = content_snippet[:3500] + "\n... [Content truncated for analysis context]"

        arts = f_info.get("artifacts", {})
        if arts.get("flags"):
            all_discovered_flags.extend(arts["flags"])
            evidence_findings.append(f"- **Flag Pattern in `{f_info['name']}`**: `{', '.join(arts['flags'])}`")
        if arts.get("base64_decoded"):
            evidence_findings.append(f"- **Base64 Decoded in `{f_info['name']}`**:\n  " + "\n  ".join(arts["base64_decoded"][:3]))
        if arts.get("hex_decoded"):
            evidence_findings.append(f"- **Hex Array Decoded in `{f_info['name']}`**:\n  " + "\n  ".join(arts["hex_decoded"][:3]))
        if arts.get("secrets"):
            evidence_findings.append(f"- **Secrets / Keywords in `{f_info['name']}`**:\n  " + "\n  ".join(arts["secrets"][:3]))

        block = (
            f"FILE:\n{f_info['name']}\n\n"
            f"METADATA:\n"
            f"- Size: {f_info['size']} bytes\n"
            f"- SHA-256: {f_info['hash']}\n"
            f"- Type: {f_info['type']}\n\n"
            f"CONTENT:\n"
            f"```\n{content_snippet}\n```\n"
            f"--------------------------------------------------"
        )
        context_blocks.append(block)

    structured_evidence_summary = (
        f"EVIDENCE REPORT:\n\n"
        f"File:\n{filename}\n\n"
        f"Contains:\n" + "\n".join([f"- {fn}" for fn in file_names_list]) + "\n\n"
        f"Key Automated Findings:\n" + ("\n".join(evidence_findings) if evidence_findings else "- No trivial plaintext/base64 flag strings detected directly. Manual algorithmic analysis required.")
    )

    full_context = structured_evidence_summary + "\n\n==================================================\n\n" + "\n\n".join(context_blocks)
    estimated_tokens = max(len(full_context) // 4, 1)

    return {
        "is_archive": is_zip,
        "archive_name": filename,
        "file_names": file_names_list,
        "file_count": len(extracted_files),
        "files_metadata": [
            {"name": f["name"], "size": f["size"], "hash": f["hash"], "type": f["type"]}
            for f in extracted_files
        ],
        "discovered_flags": list(set(all_discovered_flags)),
        "evidence_summary": structured_evidence_summary,
        "context": full_context,
        "estimated_tokens": estimated_tokens
    }
