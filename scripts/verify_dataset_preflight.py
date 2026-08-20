import json
import hashlib
from pathlib import Path
from collections import Counter

def verify_dataset_file(filepath: Path):
    print(f"\n[*] Validating: {filepath}")
    if not filepath.exists():
        print(f"[!] ERROR: File not found: {filepath}")
        return False
        
    total_lines = 0
    corrupted_lines = 0
    valid_samples = 0
    duplicate_count = 0
    seen_hashes = set()
    roles_counter = Counter()
    categories_counter = Counter()
    
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
            for msg in messages:
                if not isinstance(msg, dict) or "role" not in msg or "content" not in msg:
                    msg_valid = False
                    break
                roles_counter[msg["role"]] += 1
                
            if not msg_valid:
                print(f"  [!] Line {line_idx}: Invalid message structure")
                corrupted_lines += 1
                continue
                
            # Check duplication
            content_hash = hashlib.sha256(json.dumps(messages, sort_keys=True).encode()).hexdigest()
            if content_hash in seen_hashes:
                duplicate_count += 1
            else:
                seen_hashes.add(content_hash)
                
            cat = data.get("category", "unknown")
            categories_counter[cat] += 1
            valid_samples += 1

    print(f"  [+] Total lines:        {total_lines}")
    print(f"  [+] Valid samples:      {valid_samples}")
    print(f"  [+] Corrupted samples:  {corrupted_lines}")
    print(f"  [+] Duplicates:         {duplicate_count}")
    print(f"  [+] Roles distribution: {dict(roles_counter)}")
    print(f"  [+] Categories:         {dict(categories_counter)}")
    
    return corrupted_lines == 0 and valid_samples > 0

train_ok = verify_dataset_file(Path("dataset/merged/train.jsonl"))
val_ok = verify_dataset_file(Path("dataset/merged/val.jsonl"))

print("\n" + "=" * 70)
print(f"DATASET PRE-FLIGHT CHECK RESULT: {'PASS' if (train_ok and val_ok) else 'FAIL'}")
print("=" * 70)
