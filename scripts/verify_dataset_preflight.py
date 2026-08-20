"""
CyberQwen-AI: Production Dataset Pre-Flight & Leakage Verification Suite
Validates dataset/final/train_v2.jsonl and dataset/final/validation_v2.jsonl
for Qwen3 ChatML conformance, zero cross-split data leakage, and exact sample counts.
"""

import json
import hashlib
import argparse
from pathlib import Path
from collections import Counter

def verify_dataset_file(filepath: Path):
    print(f"\n[*] Validating: {filepath}")
    if not filepath.exists():
        print(f"[!] ERROR: File not found: {filepath}")
        return False, set(), 0
        
    total_lines = 0
    corrupted_lines = 0
    valid_samples = 0
    duplicate_count = 0
    seen_hashes = set()
    roles_counter = Counter()
    categories_counter = Counter()
    difficulties_counter = Counter()
    
    with open(filepath, "r", encoding="utf-8") as f:
        for line_idx, line in enumerate(f, 1):
            total_lines += 1
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
            except json.JSONDecodeError as e:
                print(f"  [!] Line {line_idx}: Corrupted JSON - {e}")
                corrupted_lines += 1
                continue
                
            # Check required fields
            if "messages" not in data or not isinstance(data["messages"], list):
                print(f"  [!] Line {line_idx}: Missing or invalid 'messages' field")
                corrupted_lines += 1
                continue
                
            messages = data["messages"]
            if len(messages) < 2:
                print(f"  [!] Line {line_idx}: Expected at least 2 messages (user/assistant)")
                corrupted_lines += 1
                continue
                
            msg_valid = True
            user_content = ""
            asst_content = ""
            for msg in messages:
                if not isinstance(msg, dict) or "role" not in msg or "content" not in msg:
                    msg_valid = False
                    break
                if not msg["content"] or not str(msg["content"]).strip():
                    msg_valid = False
                    break
                roles_counter[msg["role"]] += 1
                if msg["role"] == "user":
                    user_content = msg["content"].strip()
                elif msg["role"] == "assistant":
                    asst_content = msg["content"].strip()
                
            if not msg_valid or not user_content or not asst_content:
                print(f"  [!] Line {line_idx}: Invalid message structure or empty content")
                corrupted_lines += 1
                continue
                
            # Check duplication
            content_hash = hashlib.sha256(f"{user_content}|{asst_content}".encode("utf-8")).hexdigest()
            if content_hash in seen_hashes:
                duplicate_count += 1
            else:
                seen_hashes.add(content_hash)
                
            cat = data.get("category", "cybersecurity")
            diff = data.get("difficulty", "intermediate")
            categories_counter[cat] += 1
            difficulties_counter[diff] += 1
            valid_samples += 1

    print(f"  [+] Total lines:        {total_lines}")
    print(f"  [+] Valid samples:      {valid_samples}")
    print(f"  [+] Corrupted samples:  {corrupted_lines}")
    print(f"  [+] Duplicates:         {duplicate_count}")
    print(f"  [+] Roles distribution: {dict(roles_counter)}")
    print(f"  [+] Difficulties:       {dict(difficulties_counter)}")
    
    is_ok = (corrupted_lines == 0 and valid_samples > 0)
    return is_ok, seen_hashes, valid_samples

def main():
    parser = argparse.ArgumentParser(description="CyberQwen-AI: Dataset Preflight Verifier")
    parser.add_argument("--train_path", type=Path, default=Path("dataset/final/train_v2.jsonl"),
                        help="Train dataset path (default: dataset/final/train_v2.jsonl)")
    parser.add_argument("--val_path", type=Path, default=Path("dataset/final/validation_v2.jsonl"),
                        help="Validation dataset path (default: dataset/final/validation_v2.jsonl)")
    args = parser.parse_args()

    print("=" * 75)
    print("CYBERQWEN-AI: PRODUCTION DATASET INTEGRITY & PRE-FLIGHT AUDIT")
    print("=" * 75)

    train_ok, train_hashes, train_count = verify_dataset_file(args.train_path)
    val_ok, val_hashes, val_count = verify_dataset_file(args.val_path)

    # Cross-split leakage check
    overlap = train_hashes.intersection(val_hashes)
    leakage_count = len(overlap)
    print(f"\n[*] Cross-Split Overlap (Data Leakage): {leakage_count} samples (Clean Isolation: {leakage_count == 0})")

    all_ok = train_ok and val_ok and (leakage_count == 0) and (train_count == 2250) and (val_count == 250)

    print("\n" + "=" * 75)
    print("DATASET PRE-FLIGHT VERIFICATION SUMMARY:")
    print(f"  Train Samples:      {train_count} (Expected: 2250) -> {'PASS' if train_count == 2250 else 'FAIL'}")
    print(f"  Validation Samples: {val_count} (Expected: 250)  -> {'PASS' if val_count == 250 else 'FAIL'}")
    print(f"  Cross-Split Leak:   {leakage_count} (Expected: 0)    -> {'PASS' if leakage_count == 0 else 'FAIL'}")
    print(f"  Qwen3 ChatML JSONL: {'PASS' if (train_ok and val_ok) else 'FAIL'}")
    print(f"  FINAL STATUS:       {'READY FOR TRAINING' if all_ok else 'NOT READY'}")
    print("=" * 75)

if __name__ == "__main__":
    main()
