import os
import json
import hashlib
import time
import sys
from pathlib import Path
from typing import Dict, List, Set, Optional
import requests
from dotenv import load_dotenv

load_dotenv()

CATEGORIES = [
    "crypto",
    "forensics",
    "steganography",
    "osint",
    "web_exploitation",
    "reverse_engineering",
    "pwn",
    "malware_analysis",
    "linux_security",
    "secure_coding"
]

BATCH_SIZE = 10
TOTAL_PER_CATEGORY = 500
MODEL = "nvidia/nemotron-3-nano-30b-a3b"
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
OUTPUT_DIR = Path(__file__).parent.parent / "dataset" / "generated"

CATEGORY_PROMPTS = {
    "crypto": """Generate CTF-style cryptography challenges covering: classical ciphers (Caesar, Vigenere, substitution), modern crypto (AES, RSA, ECC), hash functions, digital signatures, key exchange protocols, side-channel attacks, padding oracle attacks, and cryptanalysis techniques. Include real tools like openssl, gpg, hashcat, john, sage, python cryptography libraries.""",

    "forensics": """Generate CTF-style digital forensics challenges covering: file system analysis (NTFS, FAT32, ext4), memory forensics (volatility,rekall), disk imaging (dd, ewf), artifact recovery, timeline analysis, log analysis, network forensics (pcap analysis with wireshark/tshark), malware artifacts, anti-forensics detection. Include tools: volatility, autopsy, sleuthkit, foremost, scalpel, bulk_extractor.""",

    "steganography": """Generate CTF-style steganography challenges covering: LSB embedding in images/audio/video, metadata hiding (EXIF, ID3), format-based hiding (PNG chunks, JPEG coefficients), audio steganography (echo hiding, phase coding), video steganography, network steganography, steganalysis techniques. Include tools: steghide, stegsolve, zsteg, exiftool, strings, binwalk, foremost, sonic-visualiser.""",

    "osint": """Generate CTF-style OSINT challenges covering: domain reconnaissance (whois, DNS enumeration, subdomain discovery), social media intelligence, email harvesting, breach data analysis, certificate transparency logs, internet-wide scanning (shodan, censys), geolocation, metadata extraction, username enumeration, threat intelligence. Include tools: recon-ng, theharvester, amass, subfinder, dnsrecon, sherlock, social-analyzer.""",

    "web_exploitation": """Generate CTF-style web exploitation challenges covering: OWASP Top 10 (SQLi, XSS, CSRF, SSRF, IDOR, broken auth, security misconfig, vulnerable components, logging failures), API hacking, JWT vulnerabilities, CORS misconfig, file upload bypass, deserialization, template injection (SSTI), prototype pollution, DOM clobbering. Include tools: burp suite, sqlmap, xsstrike, ffuf, dirsearch, jwt_tool, ysoserial.""",

    "reverse_engineering": """Generate CTF-style reverse engineering challenges covering: x86/x64/ARM assembly analysis, ELF/PE/Mach-O binary formats, packing/unpacking (UPX, custom), anti-debug/anti-VM, control flow obfuscation, string encryption, virtualization protectors, firmware analysis, kernel modules. Include tools: ghidra, ida pro, binary ninja, radare2, cutter, gdb, pwndbg, angr, z3.""",

    "pwn": """Generate CTF-style binary exploitation challenges covering: stack/heap overflows, format string vulnerabilities, use-after-free, double free, integer overflows, race conditions, ROP/JOP/COP chains, ret2libc, ret2dlresolve, SROP, heap feng shui, house of force/spirit/orange, bypassing ASLR/PIE/stack canaries/NX/RELRO. Include tools: pwntools, gdb/pwndbg/gef, one_gadget, libc-database, ropper, ROPgadget.""",

    "malware_analysis": """Generate CTF-style malware analysis challenges covering: static analysis (PE headers, imports, strings, resources), dynamic analysis (sandbox, API monitoring), behavior analysis (process injection, persistence, C2, lateral movement), unpacking (UPX, themida, vmprotect), shellcode analysis, C2 protocol reverse, APT attribution, YARA rule writing. Include tools: ida/ghidra, x64dbg, process hacker, procmon, regshot, wireshark, yaragen, cape, any.run.""",

    "linux_security": """Generate CTF-style Linux security challenges covering: privilege escalation (kernel exploits, SUID/SGID, sudo misconfig, capabilities, cron, path hijacking, container escape), permission hardening, SELinux/AppArmor, namespace/cgroup security, kernel module analysis, eBPF security, systemd hardening, ssh hardening, auditd, Linux capabilities. Include tools: linpeas, linux-exploit-suggester, pspy, lse, checksec.""",

    "secure_coding": """Generate CTF-style secure coding challenges covering: vulnerability identification and remediation in C/C++, Python, Java, Go, Rust, JavaScript/TypeScript; memory safety, input validation, output encoding, authentication/authorization flaws, crypto misuse, concurrency bugs, supply chain security, SAST/DAST integration, secure SDLC, threat modeling. Include code review scenarios with patches."""
}

def load_existing_hashes(file_path: Path) -> Set[str]:
    hashes = set()
    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        content = f"{data.get('instruction', '')}{data.get('input', '')}{data.get('output', '')}"
                        hashes.add(hashlib.md5(content.encode()).hexdigest())
                    except json.JSONDecodeError:
                        continue
    return hashes

def count_existing_entries(file_path: Path) -> int:
    count = 0
    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
    return count

def build_prompt(category: str, existing_count: int, batch_num: int) -> str:
    base_prompt = CATEGORY_PROMPTS.get(category, "")
    return f"""You are CyberQwen dataset engineer. Create a QLoRA fine-tuning dataset for a cybersecurity AI.

Category: {category}
Batch: {batch_num} (already generated: {existing_count} examples)

{base_prompt}

Generate exactly {BATCH_SIZE} realistic cybersecurity training examples in JSONL format.

Each line MUST be valid JSON with exactly these fields:
{{"instruction": "", "input": "", "output": ""}}

Requirements:
- CTF style challenges with realistic scenarios
- Explain methodology and reasoning step-by-step
- Include relevant tools and commands
- Include Linux commands when useful
- Explain concepts clearly and technically
- NO markdown formatting
- NO code fences (```json or ```)
- NO extra commentary
- Return ONLY raw JSONL lines
- Each example must be unique and high quality
"""

def clean_response(response: str) -> List[Dict]:
    lines = response.strip().split('\n')
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        line = line.replace("```json", "").replace("```", "").strip()
        if line.startswith('{') and line.endswith('}'):
            try:
                data = json.loads(line)
                if all(k in data for k in ['instruction', 'input', 'output']):
                    results.append(data)
            except json.JSONDecodeError:
                continue
    return results

def test_nvidia_api(api_key: str) -> bool:
    """Test NVIDIA NIM API connection with a minimal request."""
    print("Testing NVIDIA Nemotron API...")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": "Reply with OK"}],
        "temperature": 0.1,
        "top_p": 0.9,
        "max_tokens": 10
    }
    
    try:
        response = requests.post(NVIDIA_API_URL, headers=headers, json=payload, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
            print(f"NVIDIA API connection successful (response: {content.strip()})")
            return True
            
        elif response.status_code == 401:
            print("ERROR: Invalid API key (401 Unauthorized)")
            print("  Check that NVIDIA_API_KEY is correct and has access to Nemotron 3 Ultra")
            return False
            
        elif response.status_code == 403:
            print("ERROR: Access forbidden (403 Forbidden)")
            print("  Your API key doesn't have permission to use this model")
            return False
            
        elif response.status_code == 404:
            print("ERROR: Model or endpoint not found (404 Not Found)")
            print(f"  Endpoint: {NVIDIA_API_URL}")
            print(f"  Model: {MODEL}")
            print("  Verify the model name and endpoint are correct for your NVIDIA account")
            return False
            
        elif response.status_code == 429:
            print("ERROR: Rate limited (429 Too Many Requests)")
            print("  Wait before retrying or check your quota")
            return False
            
        else:
            print(f"ERROR: API request failed with status {response.status_code}")
            print(f"  Response: {response.text[:500]}")
            return False
            
    except requests.exceptions.Timeout:
        print("ERROR: Request timed out (network issue)")
        return False
    except requests.exceptions.ConnectionError:
        print("ERROR: Connection failed (network issue)")
        return False
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Request failed: {e}")
        return False
    except Exception as e:
        print(f"ERROR: Unexpected error during API test: {e}")
        return False

def handle_api_error(response: requests.Response, attempt: int, max_attempts: int) -> Optional[float]:
    """Handle API errors and return delay in seconds if retryable, None if fatal."""
    status = response.status_code
    
    if status == 401:
        print("  ERROR: Invalid API key (401 Unauthorized)")
        print("  Stopping - check NVIDIA_API_KEY in .env file")
        return None
    elif status == 403:
        print("  ERROR: Access forbidden (403 Forbidden)")
        print("  Stopping - API key lacks permission for this model")
        return None
    elif status == 404:
        print("  ERROR: Model or endpoint not found (404 Not Found)")
        print(f"  Stopping - check MODEL ({MODEL}) and endpoint ({NVIDIA_API_URL})")
        return None
    elif status == 429:
        if attempt < max_attempts - 1:
            delay = 2 ** attempt * 5
            print(f"  Rate limited (429). Retrying in {delay}s...")
            return float(delay)
        print("  Rate limited (429). Max retries reached.")
        return None
    elif status == 503:
        if attempt < max_attempts - 1:
            delay = 2 ** attempt * 10
            print(f"  Resource exhausted (503). Retrying in {delay}s...")
            return float(delay)
        print("  Resource exhausted (503). Max retries reached.")
        return None
    elif status in (500, 502, 503, 504):
        if attempt < max_attempts - 1:
            delay = 2 ** attempt
            print(f"  Server error ({status}). Retrying in {delay}s...")
            return float(delay)
        print(f"  Server error ({status}). Max retries reached.")
        return None
    else:
        print(f"  HTTP {status}: {response.text[:200]}")
        if attempt < max_attempts - 1:
            delay = 2 ** attempt
            return float(delay)
        return None

def generate_batch(category: str, existing_hashes: Set[str], batch_num: int) -> List[Dict]:
    prompt = build_prompt(category, len(existing_hashes), batch_num)
    api_key = os.getenv("NVIDIA_API_KEY")
    
    if not api_key:
        raise ValueError("NVIDIA_API_KEY not set in environment variables")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "top_p": 0.9,
        "max_tokens": 2048
    }
    
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            response = requests.post(NVIDIA_API_URL, headers=headers, json=payload, timeout=120)
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                examples = clean_response(content)
                
                unique_examples = []
                for ex in examples:
                    content_hash = hashlib.md5(
                        f"{ex['instruction']}{ex['input']}{ex['output']}".encode()
                    ).hexdigest()
                    if content_hash not in existing_hashes:
                        existing_hashes.add(content_hash)
                        unique_examples.append(ex)
                
                return unique_examples[:BATCH_SIZE]
            
            else:
                delay = handle_api_error(response, attempt, max_attempts)
                if delay is None:
                    return []
                time.sleep(delay)
                
        except requests.exceptions.Timeout:
            print(f"  Attempt {attempt + 1} failed: Request timed out")
            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)
        except requests.exceptions.ConnectionError:
            print(f"  Attempt {attempt + 1} failed: Connection error")
            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            print(f"  Attempt {attempt + 1} failed: {e}")
            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)
        except Exception as e:
            print(f"  Attempt {attempt + 1} failed: {e}")
            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)
    
    return []

def save_batch(file_path: Path, examples: List[Dict]):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "a", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

def generate_category(category: str):
    file_path = OUTPUT_DIR / f"{category}.jsonl"
    existing_hashes = load_existing_hashes(file_path)
    existing_count = count_existing_entries(file_path)
    
    print(f"\n[{category}] {existing_count}/500")
    
    if existing_count >= TOTAL_PER_CATEGORY:
        print(f"  Already complete ({existing_count}/{TOTAL_PER_CATEGORY})")
        return
    
    while existing_count < TOTAL_PER_CATEGORY:
        print(f"[{category}] {existing_count}/500")
        print(f"[{category}] requesting 10 more...")
        
        # Try to get examples, retrying if 0 returned (up to 3 attempts)
        new_examples = []
        for attempt in range(3):
            batch_examples = generate_batch(category, existing_hashes, (existing_count // BATCH_SIZE) + 1 + attempt)
            if batch_examples:
                new_examples = batch_examples
                break
        
        if new_examples:
            save_batch(file_path, new_examples)
            existing_count += len(new_examples)
            print(f"[{category}] saved {len(new_examples)}")
            print(f"[{category}] {existing_count}/500")
        else:
            print(f"  No valid examples generated, stopping category...")
            break
        
        time.sleep(3)
    
    print(f"\nCompleted: {existing_count}/{TOTAL_PER_CATEGORY} examples")

def main():
    print("CyberQwen Dataset Generator")
    print(f"Model: {MODEL}")
    print(f"Batch size: {BATCH_SIZE}")
    print(f"Target per category: {TOTAL_PER_CATEGORY}")
    print(f"Output dir: {OUTPUT_DIR}")
    
    api_key = os.getenv("NVIDIA_API_KEY")
    if not api_key:
        print("ERROR: NVIDIA_API_KEY not set in environment variables")
        print("Create a .env file with: NVIDIA_API_KEY=your_key_here")
        sys.exit(1)
    
    print("NVIDIA API key loaded")
    
    if not test_nvidia_api(api_key):
        print("\nAPI test failed. Fix the issue above and try again.")
        sys.exit(1)
    
    for category in CATEGORIES:
        generate_category(category)
    
    print("\n" + "="*60)
    print("Dataset generation complete!")
    print("="*60)
    
    for category in CATEGORIES:
        file_path = OUTPUT_DIR / f"{category}.jsonl"
        count = count_existing_entries(file_path)
        print(f"  {category}: {count}/{TOTAL_PER_CATEGORY}")

if __name__ == "__main__":
    main()