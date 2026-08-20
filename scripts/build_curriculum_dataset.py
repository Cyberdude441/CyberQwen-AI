"""
CyberQwen-AI: Curriculum Dataset Builder and Difficulty Classifier
Structures cybersecurity datasets into difficulty tiers and balanced curriculum training splits.

Tiers:
1. Beginner:     Basic definitions, standard ports, Caesar/ROT13, fundamental Linux commands, intro web terms.
2. Intermediate: CTF challenges, standard web vulnerabilities (SQLi, XSS, SSRF), Ghidra reversing, sudo privilege escalation.
3. Advanced:     ROP chains, process hollowing, padding oracle attacks, Bleichenbacher RSA, kernel privesc, custom shellcoding.
4. Expert:       Zero-day root cause analysis, heap feng-shui, kernel rootkits, hypervisor/sandbox escapes, advanced cryptographic proofs.

Training Modes:
- beginner:  Focuses on foundational cybersecurity principles and concepts.
- balanced:  20% beginner, 40% intermediate, 30% advanced, 10% expert (optimal for general-purpose assistant).
- advanced:  10% beginner, 20% intermediate, 50% advanced, 20% expert (optimal for advanced offensive/defensive ops).
"""

import os
import sys
import json
import random
import argparse
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from collections import Counter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DIFFICULTY_TIERS = ["beginner", "intermediate", "advanced", "expert"]

# Heuristic patterns for cybersecurity difficulty categorization
EXPERT_KEYWORDS = [
    r"\bheap feng\s?shui\b", r"\bzero-?day\b", r"\b0-?day\b", r"\bkernel rootkit\b",
    r"\bhypervisor escape\b", r"\bsandbox escape\b", r"\buse-?after-?free\b",
    r"\bv8 exploit\b", r"\bebp[fF] evasion\b", r"\btype confusion\b",
    r"\brtld_audit\b", r"\blattice reduction\b", r"\bcoppersmith\b", r"\bhåstad\b",
    r"\bblind sqli\b", r"\bbinary exploitation\b", r"\brop chain\b", r"\bkernel\b",
    r"\baslr bypass\b", r"\bformat string\b", r"\bdep bypass\b", r"\bseh overwrite\b"
]

ADVANCED_KEYWORDS = [
    r"\brop\b", r"\breturn-?oriented\b", r"\bprocess hollowing\b", r"\bbleichenbacher\b",
    r"\bpadding oracle\b", r"\bshellcode\b", r"\bbuffer overflow\b", r"\baslr\b",
    r"\bvolatility\b", r"\bmalfind\b", r"\bekko\b", r"\bfoliage\b", r"\bcobalt strike\b",
    r"\bgadget\b", r"\bptrace_traceme\b", r"\bgdb-peda\b", r"\bpwntools\b", r"\bimdsv2\b",
    r"\brsa\b", r"\belliptic curve\b", r"\becc\b", r"\bdiffie-?hellman\b", r"\baes-?gcm\b",
    r"\bdisassembl\w+\b", r"\breverse engineer\w+\b", r"\bghidra\b", r"\bdecompil\w+\b",
    r"\bprivilege escalation\b", r"\bgtfobins\b", r"\bdeserialization\b", r"\bpayload\b"
]

INTERMEDIATE_KEYWORDS = [
    r"\bctf\b", r"\brxss\b", r"\bxss\b", r"\bsqli\b", r"\bsql injection\b",
    r"\bssrf\b", r"\bcsrf\b", r"\bsuid\b", r"\bsudoers\b", r"\bburp\b",
    r"\bwireshark\b", r"\bzsteg\b", r"\bbinwalk\b", r"\bpngcheck\b", r"\bnmap\b",
    r"\bhashcat\b", r"\bjohn the ripper\b", r"\bdirsearch\b", r"\bvigenère\b",
    r"\bcaesar\b", r"\brot13\b", r"\bbase64\b", r"\bsha256\b", r"\bmd5\b",
    r"\bforensics\b", r"\bsteganograph\w+\b", r"\bosint\b", r"\bwhois\b", r"\bdns\b"
]

def infer_difficulty_heuristics(example: Dict) -> str:
    """Infers difficulty based on technical vocabulary and exploit mechanics."""
    inst = example.get("instruction", "").lower()
    inp = example.get("input", "").lower()
    out = example.get("output", "").lower()
    full_text = f"{inst}\n{inp}\n{out}"

    # 1. Check for Expert markers
    for pattern in EXPERT_KEYWORDS:
        if re.search(pattern, full_text, re.IGNORECASE):
            return "expert"

    # 2. Check for Advanced markers
    adv_matches = sum(1 for p in ADVANCED_KEYWORDS if re.search(p, full_text, re.IGNORECASE))
    if adv_matches >= 2 or (len(out) > 800 and adv_matches >= 1):
        return "advanced"

    # 3. Check for Intermediate markers
    int_matches = sum(1 for p in INTERMEDIATE_KEYWORDS if re.search(p, full_text, re.IGNORECASE))
    if int_matches >= 1 or adv_matches == 1 or len(out) > 300:
        return "intermediate"

    # 4. Fallback to beginner
    return "beginner"

def load_and_classify_cleaned_datasets(
    cleaned_dir: Path,
    use_heuristics: bool = True
) -> Tuple[Dict[str, List[Dict]], List[Dict]]:
    """Loads all cleaned datasets and groups them by difficulty tier."""
    by_difficulty = {tier: [] for tier in DIFFICULTY_TIERS}
    all_examples = []

    if not cleaned_dir.exists():
        raise FileNotFoundError(f"Cleaned dataset directory not found: {cleaned_dir}")

    jsonl_files = sorted(cleaned_dir.rglob("*.jsonl"))
    print(f"[*] Loading datasets from {cleaned_dir} ({len(jsonl_files)} files found)...")

    for jsonl_file in jsonl_files:
        cat_name = jsonl_file.stem
        with open(jsonl_file, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if "instruction" in data and "output" in data:
                        data["_category"] = data.get("category", cat_name)
                        diff = data.get("difficulty")
                        if not diff or diff not in DIFFICULTY_TIERS:
                            if use_heuristics:
                                diff = infer_difficulty_heuristics(data)
                            else:
                                diff = "intermediate"
                        
                        data["difficulty"] = diff
                        by_difficulty[diff].append(data)
                        all_examples.append(data)
                except json.JSONDecodeError:
                    pass

    return by_difficulty, all_examples

def format_for_qwen(example: Dict) -> Dict:
    """Formats an example into Qwen3 messages structure."""
    instruction = example["instruction"].strip()
    inp = example.get("input", "").strip()
    output = example["output"].strip()
    
    user_content = f"{instruction}\n\n{inp}".strip() if inp else instruction
    
    return {
        "messages": [
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": output}
        ],
        "category": example.get("_category", example.get("category", "unknown")),
        "difficulty": example.get("difficulty", "intermediate")
    }

def save_jsonl(file_path: Path, examples: List[Dict], as_chat: bool = True):
    """Saves examples to a JSONL file."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        for ex in examples:
            if as_chat:
                formatted = format_for_qwen(ex)
                f.write(json.dumps(formatted, ensure_ascii=False) + "\n")
            else:
                clean_ex = {k: v for k, v in ex.items() if not k.startswith("_")}
                f.write(json.dumps(clean_ex, ensure_ascii=False) + "\n")

def sample_curriculum_split(
    by_difficulty: Dict[str, List[Dict]],
    weights: Dict[str, float],
    target_count: Optional[int] = None,
    seed: int = 42
) -> List[Dict]:
    """Samples a weighted blend of difficulty tiers for curriculum learning."""
    random.seed(seed)
    selected = []

    # If target_count not set, use maximum available based on proportions
    if not target_count:
        total_available = sum(len(v) for v in by_difficulty.values())
        target_count = total_available

    for tier, ratio in weights.items():
        pool = by_difficulty.get(tier, []).copy()
        random.shuffle(pool)
        desired = int(target_count * ratio)
        
        # If pool has fewer than desired, take all and warn/backfill
        if len(pool) <= desired:
            selected.extend(pool)
        else:
            selected.extend(pool[:desired])

    random.shuffle(selected)
    return selected

def generate_difficulty_distribution_report(
    by_difficulty: Dict[str, List[Dict]],
    total_count: int,
    output_path: Path
):
    """Generates dataset/reports/difficulty_distribution.json."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    tier_stats = {}
    for tier in DIFFICULTY_TIERS:
        examples = by_difficulty.get(tier, [])
        cat_counter = Counter(ex.get("_category", "unknown") for ex in examples)
        pct = (len(examples) / total_count * 100) if total_count > 0 else 0.0
        
        tier_stats[tier] = {
            "count": len(examples),
            "percentage": round(pct, 1),
            "categories": dict(cat_counter)
        }

    report = {
        "timestamp": os.path.basename(str(output_path)),
        "total_dataset_size": total_count,
        "difficulty_distribution": tier_stats,
        "recommended_training_modes": {
            "balanced": "20% beginner, 40% intermediate, 30% advanced, 10% expert",
            "advanced": "10% beginner, 20% intermediate, 50% advanced, 20% expert",
            "beginner": "70% beginner, 30% intermediate"
        }
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    
    print(f"[+] Difficulty distribution report saved to: {output_path}")
    return report

def main():
    parser = argparse.ArgumentParser(description="CyberQwen-AI: Curriculum Dataset Builder & Difficulty Classifier")
    parser.add_argument("--input-dir", type=Path, default=Path("dataset/cleaned"),
                        help="Input directory containing cleaned datasets (default: dataset/cleaned)")
    parser.add_argument("--output-dir", type=Path, default=Path("dataset/curriculum"),
                        help="Output directory for curriculum datasets (default: dataset/curriculum)")
    parser.add_argument("--report-file", type=Path, default=Path("dataset/reports/difficulty_distribution.json"),
                        help="Path to difficulty distribution report (default: dataset/reports/difficulty_distribution.json)")
    parser.add_argument("--mode", choices=["beginner", "balanced", "advanced", "all"], default="balanced",
                        help="Curriculum training mode (default: balanced)")
    parser.add_argument("--train-ratio", type=float, default=0.9,
                        help="Train/val split ratio (default: 0.9)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    args = parser.parse_args()

    print("\n" + "=" * 75)
    print("CYBERQWEN-AI: CURRICULUM DATASET BUILDER")
    print("=" * 75)
    print(f"[*] Input Directory:   {args.input_dir}")
    print(f"[*] Output Directory:  {args.output_dir}")
    print(f"[*] Training Mode:     {args.mode.upper()}")
    print(f"[*] Train Ratio:       {args.train_ratio}")
    print("=" * 75 + "\n")

    # 1. Load and Classify Datasets
    by_difficulty, all_examples = load_and_classify_cleaned_datasets(args.input_dir)
    total_count = len(all_examples)

    print("\n" + "=" * 75)
    print(f"DIFFICULTY CLASSIFICATION SUMMARY (Total: {total_count} examples)")
    print("=" * 75)
    for tier in DIFFICULTY_TIERS:
        count = len(by_difficulty[tier])
        pct = (count / total_count * 100) if total_count > 0 else 0.0
        print(f"  {tier.capitalize():<15} {count:>6} examples ({pct:>5.1f}%)")
    print("=" * 75 + "\n")

    # 2. Save Discrete Tier JSONL Files
    print("[*] Saving discrete tier datasets to dataset/curriculum/...")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for tier in DIFFICULTY_TIERS:
        tier_file = args.output_dir / f"{tier}.jsonl"
        save_jsonl(tier_file, by_difficulty[tier], as_chat=True)
        print(f"  [+] Saved {tier:<12} -> {tier_file} ({len(by_difficulty[tier])} samples)")

    # 3. Generate Difficulty Distribution Report
    generate_difficulty_distribution_report(by_difficulty, total_count, args.report_file)

    # 4. Generate Training Mode Curriculum Splits
    modes_to_build = [args.mode] if args.mode != "all" else ["beginner", "balanced", "advanced"]

    curriculum_weights = {
        "balanced": {"beginner": 0.20, "intermediate": 0.40, "advanced": 0.30, "expert": 0.10},
        "advanced": {"beginner": 0.10, "intermediate": 0.20, "advanced": 0.50, "expert": 0.20},
        "beginner": {"beginner": 0.70, "intermediate": 0.30, "advanced": 0.00, "expert": 0.00}
    }

    for m in modes_to_build:
        weights = curriculum_weights[m]
        print(f"\n[*] Building '{m}' curriculum split (Weights: {weights})...")
        sampled = sample_curriculum_split(by_difficulty, weights, target_count=total_count, seed=args.seed)
        
        # Split into train and val
        random.seed(args.seed)
        random.shuffle(sampled)
        split_idx = int(len(sampled) * args.train_ratio)
        train_set = sampled[:split_idx]
        val_set = sampled[split_idx:]

        train_file = args.output_dir / f"{m}_train.jsonl"
        val_file = args.output_dir / f"{m}_val.jsonl"

        save_jsonl(train_file, train_set, as_chat=True)
        save_jsonl(val_file, val_set, as_chat=True)

        print(f"  [+] {m.capitalize()} Train: {len(train_set)} samples -> {train_file}")
        print(f"  [+] {m.capitalize()} Val:   {len(val_set)} samples -> {val_file}")

    print("\n" + "=" * 75)
    print("✅ CURRICULUM DATASET BUILD COMPLETED!")
    print(f"[*] Datasets saved in: {args.output_dir}")
    print(f"[*] To train with balanced curriculum:")
    print(f"    python scripts/train_qlora.py --train_path {args.output_dir}/balanced_train.jsonl --val_path {args.output_dir}/balanced_val.jsonl")
    print("=" * 75 + "\n")

if __name__ == "__main__":
    main()
