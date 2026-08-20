import json
import hashlib
import re
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import Counter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DATASET_DIR = Path(__file__).parent.parent / "dataset"
CLEANED_DIR = DATASET_DIR / "cleaned"

MIN_INSTRUCTION_LEN = 20
MIN_OUTPUT_LEN = 50
MAX_INSTRUCTION_LEN = 2000
MAX_OUTPUT_LEN = 8000
MIN_INPUT_LEN = 0
MAX_INPUT_LEN = 4000

LOW_QUALITY_PATTERNS = [
    r"^here is the",
    r"^here are the",
    r"^below is",
    r"^the answer is",
    r"^as an ai",
    r"^i cannot",
    r"^i don't know",
    r"^not sure",
    r"^maybe",
    r"^i think",
    r"^probably",
    r"^\w{1,5}$",
    r"^.{1,10}$",
]

REQUIRED_FIELDS = ["instruction", "input", "output"]

def is_low_quality(text: str, field: str) -> bool:
    if not text or not text.strip():
        return True
    
    text = text.strip()
    
    if field == "instruction" and len(text) < MIN_INSTRUCTION_LEN:
        return True
    if field == "output" and len(text) < MIN_OUTPUT_LEN:
        return True
    if field == "instruction" and len(text) > MAX_INSTRUCTION_LEN:
        return True
    if field == "output" and len(text) > MAX_OUTPUT_LEN:
        return True
    if field == "input" and len(text) > MAX_INPUT_LEN:
        return True
    
    for pattern in LOW_QUALITY_PATTERNS:
        if re.match(pattern, text, re.IGNORECASE):
            return True
    
    alpha_count = sum(1 for c in text if c.isalpha())
    if len(text) > 20 and alpha_count / len(text) < 0.3:
        return True
    
    return False

def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = text.strip()
    return text

def normalize_example(example: Dict) -> Optional[Dict]:
    normalized = {}
    for field in REQUIRED_FIELDS:
        value = example.get(field, "")
        if not isinstance(value, str):
            value = str(value) if value is not None else ""
        normalized[field] = normalize_text(value)
    
    if is_low_quality(normalized["instruction"], "instruction"):
        return None
    if is_low_quality(normalized["output"], "output"):
        return None
    if normalized["input"] and is_low_quality(normalized["input"], "input"):
        return None
    
    return normalized

def load_jsonl(file_path: Path) -> List[Dict]:
    examples = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                examples.append(data)
            except json.JSONDecodeError:
                pass
    return examples

def save_jsonl(file_path: Path, examples: List[Dict]):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

def clean_file(input_path: Path, output_path: Path, global_hashes: Set[str]) -> Tuple[int, int, int, int]:
    examples = load_jsonl(input_path)
    total = len(examples)
    
    normalized = []
    for ex in examples:
        norm = normalize_example(ex)
        if norm:
            normalized.append(norm)
    normalized_count = len(normalized)
    
    unique = []
    seen_hashes = set()
    for ex in normalized:
        content = f"{ex['instruction']}{ex['input']}{ex['output']}"
        content_hash = hashlib.md5(content.encode()).hexdigest()
        if content_hash not in seen_hashes and content_hash not in global_hashes:
            seen_hashes.add(content_hash)
            global_hashes.add(content_hash)
            unique.append(ex)
    unique_count = len(unique)
    
    save_jsonl(output_path, unique)
    
    return total, normalized_count, unique_count, total - unique_count

def clean_category(category_dir: Path, output_base: Path, global_hashes: Set[str]) -> Dict:
    results = {"files": 0, "total": 0, "normalized": 0, "unique": 0, "removed": 0}
    
    for jsonl_file in category_dir.glob("*.jsonl"):
        rel_path = jsonl_file.relative_to(category_dir.parent)
        output_file = output_base / rel_path
        
        total, normalized, unique, removed = clean_file(jsonl_file, output_file, global_hashes)
        
        results["files"] += 1
        results["total"] += total
        results["normalized"] += normalized
        results["unique"] += unique
        results["removed"] += removed
        
        print(f"  {rel_path}: {total} -> {unique} (removed: {removed})")
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Clean and normalize CyberQwen dataset")
    parser.add_argument("--input-dir", type=Path, default=DATASET_DIR,
                        help="Input dataset directory")
    parser.add_argument("--output-dir", type=Path, default=CLEANED_DIR,
                        help="Output cleaned dataset directory")
    parser.add_argument("--categories", nargs="+", 
                        default=["crypto", "forensics", "steganography", "osint", 
                                "web_exploitation", "reverse_engineering", "pwn", 
                                "malware_analysis", "linux_security", "secure_coding",
                                "web_security", "vulnerability_reports", "ctf"],
                        help="Categories to clean")
    args = parser.parse_args()
    
    print(f"\n{'='*70}")
    print(f"CLEANING DATASET")
    print(f"Input:  {args.input_dir}")
    print(f"Output: {args.output_dir}")
    print(f"{'='*70}")
    
    global_hashes = set()
    all_results = {}
    
    for category in args.categories:
        category_path = args.input_dir / category
        if not category_path.exists():
            print(f"\n⚠️  Category not found: {category}")
            continue
        
        print(f"\n📁 Cleaning: {category}")
        output_category = args.output_dir / category
        results = clean_category(category_path, args.output_dir, global_hashes)
        all_results[category] = results
    
    print(f"\n{'='*70}")
    print("CLEANING SUMMARY")
    print(f"{'='*70}")
    print(f"{'Category':<25} {'Files':>6} {'Total':>8} {'Normalized':>10} {'Unique':>8} {'Removed':>8}")
    print("-" * 70)
    
    grand_total = {"files": 0, "total": 0, "normalized": 0, "unique": 0, "removed": 0}
    for cat, results in sorted(all_results.items()):
        print(f"{cat:<25} {results['files']:>6} {results['total']:>8} {results['normalized']:>10} {results['unique']:>8} {results['removed']:>8}")
        for k in grand_total:
            grand_total[k] += results[k]
    
    print("-" * 70)
    print(f"{'TOTAL':<25} {grand_total['files']:>6} {grand_total['total']:>8} {grand_total['normalized']:>10} {grand_total['unique']:>8} {grand_total['removed']:>8}")
    print(f"\n✅ Cleaned dataset saved to: {args.output_dir}")

if __name__ == "__main__":
    main()