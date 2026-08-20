import json
import os
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import Counter

REQUIRED_FIELDS = ["instruction", "input", "output"]
DATASET_DIR = Path(__file__).parent.parent / "dataset"

def validate_jsonl(file_path: Path) -> Tuple[int, int, List[str], Dict]:
    errors = []
    line_count = 0
    valid_count = 0
    field_stats = Counter()
    hashes = set()
    duplicates = 0
    
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            line_count += 1
            
            try:
                data = json.loads(line)
                valid_count += 1
                
                for field in REQUIRED_FIELDS:
                    if field not in data:
                        errors.append(f"Line {line_num}: Missing field '{field}'")
                    elif not data[field] or not data[field].strip():
                        errors.append(f"Line {line_num}: Empty field '{field}'")
                    else:
                        field_stats[field] += 1
                
                content = f"{data.get('instruction', '')}{data.get('input', '')}{data.get('output', '')}"
                content_hash = hashlib.md5(content.encode()).hexdigest()
                if content_hash in hashes:
                    duplicates += 1
                    errors.append(f"Line {line_num}: Duplicate content (hash: {content_hash[:8]})")
                else:
                    hashes.add(content_hash)
                
                if any("```" in str(data.get(f, "")) for f in REQUIRED_FIELDS):
                    errors.append(f"Line {line_num}: Contains markdown code fences")
                
            except json.JSONDecodeError as e:
                errors.append(f"Line {line_num}: Invalid JSON - {e}")
    
    return line_count, valid_count, errors, {"field_stats": field_stats, "duplicates": duplicates}

def check_category_balance(dataset_dir: Path) -> Dict[str, int]:
    counts = {}
    for category_dir in dataset_dir.iterdir():
        if category_dir.is_dir():
            for jsonl_file in category_dir.glob("*.jsonl"):
                count = 0
                with open(jsonl_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            count += 1
                counts[category_dir.name] = count
    return counts

def validate_all(dataset_dir: Path = DATASET_DIR, verbose: bool = False) -> bool:
    print(f"\n{'='*70}")
    print(f"VALIDATING DATASET: {dataset_dir}")
    print(f"{'='*70}")
    
    all_errors = []
    total_lines = 0
    total_valid = 0
    category_stats = {}
    
    for root, dirs, files in os.walk(dataset_dir):
        for file in files:
            if file.endswith(".jsonl"):
                file_path = Path(root) / file
                rel_path = file_path.relative_to(dataset_dir)
                
                line_count, valid_count, errors, stats = validate_jsonl(file_path)
                total_lines += line_count
                total_valid += valid_count
                
                category = str(rel_path.parent)
                if category not in category_stats:
                    category_stats[category] = {"files": 0, "lines": 0, "valid": 0, "duplicates": 0}
                category_stats[category]["files"] += 1
                category_stats[category]["lines"] += line_count
                category_stats[category]["valid"] += valid_count
                category_stats[category]["duplicates"] += stats["duplicates"]
                
                if errors:
                    all_errors.extend([f"{rel_path}: {e}" for e in errors])
                    if verbose:
                        print(f"\n❌ {rel_path}: {len(errors)} errors")
                        for e in errors[:10]:
                            print(f"   - {e}")
                        if len(errors) > 10:
                            print(f"   ... and {len(errors) - 10} more")
                else:
                    if verbose:
                        print(f"✅ {rel_path}: {valid_count} valid entries")
    
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Total lines:     {total_lines}")
    print(f"Valid entries:   {total_valid}")
    print(f"Invalid entries: {total_lines - total_valid}")
    print(f"Categories:      {len(category_stats)}")
    
    print(f"\n{'Category':<30} {'Files':>6} {'Lines':>8} {'Valid':>8} {'Duplicates':>10}")
    print("-" * 65)
    for cat, stats in sorted(category_stats.items()):
        print(f"{cat:<30} {stats['files']:>6} {stats['lines']:>8} {stats['valid']:>8} {stats['duplicates']:>10}")
    
    if all_errors:
        print(f"\n❌ VALIDATION FAILED: {len(all_errors)} total errors")
        if not verbose:
            print("\nFirst 20 errors:")
            for e in all_errors[:20]:
                print(f"  - {e}")
            if len(all_errors) > 20:
                print(f"  ... and {len(all_errors) - 20} more")
        return False
    else:
        print(f"\n✅ VALIDATION PASSED: All {total_valid} entries are valid")
        return True

def main():
    parser = argparse.ArgumentParser(description="Validate CyberQwen dataset")
    parser.add_argument("--dataset-dir", type=Path, default=DATASET_DIR,
                        help="Dataset directory to validate")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output")
    args = parser.parse_args()
    
    success = validate_all(args.dataset_dir, args.verbose)
    exit(0 if success else 1)

if __name__ == "__main__":
    main()