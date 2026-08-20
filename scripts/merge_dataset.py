import json
import random
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Tuple
from collections import Counter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

CLEANED_DIR = Path(__file__).parent.parent / "dataset" / "cleaned"
MERGED_DIR = Path(__file__).parent.parent / "dataset" / "merged"

REQUIRED_FIELDS = ["instruction", "input", "output"]

def load_all_jsonl(input_dir: Path) -> List[Dict]:
    all_examples = []
    category_counts = Counter()
    
    for category_dir in sorted(input_dir.iterdir()):
        if not category_dir.is_dir():
            continue
        
        for jsonl_file in sorted(category_dir.glob("*.jsonl")):
            with open(jsonl_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if all(f in data for f in REQUIRED_FIELDS):
                            data["_category"] = category_dir.name
                            all_examples.append(data)
                            category_counts[category_dir.name] += 1
                    except json.JSONDecodeError:
                        pass
    
    return all_examples, category_counts

def format_for_qwen3(example: Dict) -> Dict:
    instruction = example["instruction"].strip()
    input_text = example["input"].strip() if example["input"] else ""
    output = example["output"].strip()
    
    if input_text:
        user_content = f"{instruction}\n\n{input_text}"
    else:
        user_content = instruction
    
    return {
        "messages": [
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": output}
        ],
        "category": example.get("_category", "unknown")
    }

def save_jsonl(file_path: Path, examples: List[Dict]):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

def save_raw_jsonl(file_path: Path, examples: List[Dict]):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        for ex in examples:
            raw = {k: v for k, v in ex.items() if k != "_category"}
            f.write(json.dumps(raw, ensure_ascii=False) + "\n")

def split_dataset(examples: List[Dict], train_ratio: float = 0.9, seed: int = 42) -> Tuple[List[Dict], List[Dict]]:
    random.seed(seed)
    shuffled = examples.copy()
    random.shuffle(shuffled)
    
    split_idx = int(len(shuffled) * train_ratio)
    train = shuffled[:split_idx]
    val = shuffled[split_idx:]
    
    return train, val

def print_stats(name: str, examples: List[Dict]):
    categories = Counter(ex.get("category", ex.get("_category", "unknown")) for ex in examples)
    total = len(examples)
    
    print(f"\n{name}: {total} examples")
    print(f"  Categories: {len(categories)}")
    for cat, count in sorted(categories.items()):
        pct = (count / total) * 100 if total > 0 else 0
        print(f"    {cat:<25} {count:>6} ({pct:>5.1f}%)")
    
    if not examples:
        return
        
    if "messages" in examples[0]:
        lens_inst = [len(ex["messages"][0]["content"]) for ex in examples]
        lens_out = [len(ex["messages"][1]["content"]) for ex in examples]
    else:
        lens_inst = [len(ex.get("instruction", "") + ex.get("input", "")) for ex in examples]
        lens_out = [len(ex.get("output", "")) for ex in examples]
        
    print(f"  Avg instruction len: {sum(lens_inst)/len(lens_inst):.0f} chars")
    print(f"  Avg output len:      {sum(lens_out)/len(lens_out):.0f} chars")
    print(f"  Max instruction len: {max(lens_inst)} chars")
    print(f"  Max output len:      {max(lens_out)} chars")

def create_category_splits(examples: List[Dict], output_dir: Path, train_ratio: float = 0.9, seed: int = 42):
    by_category = {}
    for ex in examples:
        cat = ex.get("category", "unknown")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(ex)
    
    for cat, cat_examples in by_category.items():
        random.seed(seed)
        random.shuffle(cat_examples)
        split_idx = int(len(cat_examples) * train_ratio)
        
        train = cat_examples[:split_idx]
        val = cat_examples[split_idx:]
        
        save_jsonl(output_dir / f"train_{cat}.jsonl", train)
        save_jsonl(output_dir / f"val_{cat}.jsonl", val)
        
        print(f"  {cat}: train={len(train)}, val={len(val)}")

def main():
    parser = argparse.ArgumentParser(description="Merge and split CyberQwen dataset for QLoRA")
    parser.add_argument("--input-dir", type=Path, default=CLEANED_DIR,
                        help="Input cleaned dataset directory")
    parser.add_argument("--output-dir", type=Path, default=MERGED_DIR,
                        help="Output merged dataset directory")
    parser.add_argument("--train-ratio", type=float, default=0.9,
                        help="Train split ratio (default: 0.9)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for splitting (default: 42)")
    parser.add_argument("--format", choices=["qwen3", "raw", "both"], default="both",
                        help="Output format: qwen3 (chat template), raw (instruction/input/output), or both")
    parser.add_argument("--per-category", action="store_true",
                        help="Also create per-category train/val splits")
    args = parser.parse_args()
    
    print(f"\n{'='*70}")
    print(f"MERGING DATASET FOR QLORA FINE-TUNING")
    print(f"Input:       {args.input_dir}")
    print(f"Output:      {args.output_dir}")
    print(f"Train ratio: {args.train_ratio}")
    print(f"Seed:        {args.seed}")
    print(f"Format:      {args.format}")
    print(f"{'='*70}")
    
    print("\n📥 Loading all examples...")
    all_examples, category_counts = load_all_jsonl(args.input_dir)
    print(f"   Loaded {len(all_examples)} examples from {len(category_counts)} categories")
    
    for cat, count in sorted(category_counts.items()):
        print(f"   {cat:<25} {count:>6}")
    
    print("\n🔀 Shuffling and splitting...")
    train_examples, val_examples = split_dataset(all_examples, args.train_ratio, args.seed)
    
    print(f"   Train: {len(train_examples)}")
    print(f"   Val:   {len(val_examples)}")
    
    if args.format in ["qwen3", "both"]:
        print("\n💾 Saving Qwen3 chat format...")
        train_qwen3 = [format_for_qwen3(ex) for ex in train_examples]
        val_qwen3 = [format_for_qwen3(ex) for ex in val_examples]
        
        save_jsonl(args.output_dir / "train.jsonl", train_qwen3)
        save_jsonl(args.output_dir / "val.jsonl", val_qwen3)
        print(f"   Saved: {args.output_dir}/train.jsonl")
        print(f"   Saved: {args.output_dir}/val.jsonl")
    
    if args.format in ["raw", "both"]:
        print("\n💾 Saving raw instruction format...")
        save_raw_jsonl(args.output_dir / "train_raw.jsonl", train_examples)
        save_raw_jsonl(args.output_dir / "val_raw.jsonl", val_examples)
        print(f"   Saved: {args.output_dir}/train_raw.jsonl")
        print(f"   Saved: {args.output_dir}/val_raw.jsonl")
    
    if args.per_category:
        print("\n💾 Creating per-category splits...")
        cat_dir = args.output_dir / "by_category"
        create_category_splits(train_examples + val_examples, cat_dir, args.train_ratio, args.seed)
        print(f"   Saved to: {cat_dir}")
    
    print("\n" + "="*70)
    print("SPLIT STATISTICS")
    print("="*70)
    print_stats("TRAIN", train_examples)
    print_stats("VALIDATION", val_examples)
    
    print(f"\n✅ Done! Dataset ready for QLoRA fine-tuning Qwen3-8B")
    print(f"   Use: {args.output_dir}/train.jsonl and {args.output_dir}/val.jsonl")

if __name__ == "__main__":
    main()