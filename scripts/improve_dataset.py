"""
CyberQwen-AI: Dataset Quality Improvement Pipeline via Google Gemini with Quality Tracking
Processes synthetic datasets, filters out low-quality/incorrect samples, rewrites/improves examples,
and generates structured quality audit reports in dataset/reports/.

Workflow:
dataset/generated/*.jsonl -> Gemini Review & Scoring -> dataset/cleaned/*.jsonl
                                                    └──> dataset/reports/*_quality_report.json
"""

import os
import sys
import json
import time
import argparse
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Any
from dotenv import load_dotenv

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Add scripts directory to path to import gemini_validator
sys.path.insert(0, str(Path(__file__).parent))
from gemini_validator import test_gemini_connection, validate_example, improve_example

load_dotenv()

def compute_example_hash(example: Dict) -> str:
    """Computes a SHA256 content hash for duplicate detection."""
    content = f"{example.get('instruction', '').strip().lower()}{example.get('input', '').strip().lower()}{example.get('output', '').strip().lower()}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def process_file(
    input_file: Path,
    output_file: Path,
    report_dir: Path = Path("dataset/reports"),
    min_score: float = 7.0,
    auto_improve: bool = True,
    max_samples: Optional[int] = None,
    delay: float = 1.0,
    seen_hashes: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Processes a single JSONL dataset file with Gemini quality validation and stores tracking reports.
    """
    if seen_hashes is None:
        seen_hashes = set()

    category = input_file.stem
    print("\n" + "=" * 75)
    print(f"PROCESSING DATASET: {input_file.name} (Category: {category})")
    print(f"Input:       {input_file}")
    print(f"Output:      {output_file}")
    print(f"Reports:     {report_dir / f'{category}_quality_report.json'}")
    print(f"Min Score:   {min_score}/10.0")
    print(f"Auto-Improve: {'ENABLED' if auto_improve else 'DISABLED'}")
    print("=" * 75)

    if not input_file.exists():
        print(f"[!] ERROR: Input file not found: {input_file}")
        return {"total": 0, "accepted": 0, "improved": 0, "rejected": 0, "duplicates": 0, "avg_score": 0.0, "category": category}

    # Load raw lines
    raw_examples = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if "instruction" in data and "output" in data:
                    raw_examples.append(data)
            except json.JSONDecodeError:
                pass

    total_count = len(raw_examples)
    if max_samples:
        raw_examples = raw_examples[:max_samples]

    print(f"[*] Loaded {len(raw_examples)} examples (from {total_count} total lines)")

    cleaned_examples = []
    sample_reports = []
    original_scores = []
    final_scores = []

    stats = {
        "category": category,
        "total": len(raw_examples),
        "accepted": 0,
        "improved": 0,
        "rejected": 0,
        "duplicates": 0,
        "original_scores": [],
        "final_scores": []
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    for idx, ex in enumerate(raw_examples, 1):
        sample_id = f"{category}_{idx:04d}"
        inst_preview = ex["instruction"][:60].replace("\n", " ")
        print(f"\n[{idx:>3}/{len(raw_examples)}] [{sample_id}] Inspecting: \"{inst_preview}...\"")

        # 1. Duplicate Check
        h = compute_example_hash(ex)
        if h in seen_hashes:
            print(f"    -> [REJECTED] Duplicate example detected.")
            stats["duplicates"] += 1
            stats["rejected"] += 1
            sample_reports.append({
                "id": sample_id,
                "category": category,
                "original_score": 0.0,
                "final_score": 0.0,
                "issues": ["Duplicate content detected in dataset."],
                "improvements": [],
                "accepted": False
            })
            continue

        # 2. Gemini Quality Validation
        eval_result = validate_example(ex)
        orig_score = eval_result["score"]
        quality = eval_result["quality"]
        difficulty = eval_result.get("difficulty", "intermediate")
        issues = eval_result["issues"]
        suggestion = eval_result["suggestion"]

        stats["original_scores"].append(orig_score)
        print(f"    -> Original Score: {orig_score:>4.1f}/10.0 | Quality: {quality.upper()} | Difficulty: {difficulty.upper()}")
        if issues:
            print(f"    -> Issues: {', '.join(issues[:2])}")

        # 3. Decision & Auto-Improvement Logic
        improvements_made = []
        is_accepted = False
        final_score = orig_score
        final_diff = difficulty

        if orig_score >= min_score and quality == "good":
            print(f"    -> [ACCEPTED] High quality cybersecurity sample.")
            ex["difficulty"] = difficulty
            cleaned_examples.append(ex)
            seen_hashes.add(h)
            stats["accepted"] += 1
            is_accepted = True
            improvements_made.append("Passed initial validation without modification.")
        elif auto_improve and (orig_score >= 3.0 or issues):
            print(f"    -> [IMPROVING] Calling Gemini to rewrite and elevate technical depth...")
            improved_ex = improve_example(ex, feedback=eval_result)
            
            # Re-validate improved sample
            re_eval = validate_example(improved_ex)
            re_score = re_eval["score"]
            final_diff = re_eval.get("difficulty", difficulty)
            print(f"    -> Post-Improvement Score: {re_score:>4.1f}/10.0 | Difficulty: {final_diff.upper()}")
            
            if re_score >= min_score or re_score > orig_score:
                improved_ex["difficulty"] = final_diff
                cleaned_examples.append(improved_ex)
                seen_hashes.add(compute_example_hash(improved_ex))
                stats["improved"] += 1
                stats["accepted"] += 1
                is_accepted = True
                final_score = re_score
                improvements_made.append(f"Rewritten with step-by-step reasoning and technical tooling. (Score {orig_score:.1f} -> {re_score:.1f})")
                if suggestion:
                    improvements_made.append(f"Applied suggestion: {suggestion}")
                print(f"    -> [ACCEPTED] Successfully improved sample.")
            else:
                stats["rejected"] += 1
                final_score = re_score
                print(f"    -> [REJECTED] Sample did not reach quality threshold after rewrite.")
        else:
            print(f"    -> [REJECTED] Quality score ({orig_score:.1f}) below threshold ({min_score}).")
            stats["rejected"] += 1

        stats["final_scores"].append(final_score)

        # Store metadata entry
        sample_reports.append({
            "id": sample_id,
            "category": category,
            "difficulty": final_diff,
            "original_score": round(orig_score, 1),
            "final_score": round(final_score, 1),
            "issues": issues,
            "improvements": improvements_made,
            "accepted": is_accepted
        })

        # Rate limiting delay
        if delay > 0 and idx < len(raw_examples):
            time.sleep(delay)

    # Save cleaned examples to JSONL output
    with open(output_file, "w", encoding="utf-8") as f:
        for ex in cleaned_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    avg_orig = sum(stats["original_scores"]) / len(stats["original_scores"]) if stats["original_scores"] else 0.0
    avg_final = sum(stats["final_scores"]) / len(stats["final_scores"]) if stats["final_scores"] else 0.0
    stats["avg_original_score"] = round(avg_orig, 2)
    stats["avg_final_score"] = round(avg_final, 2)

    # Save structured category quality report to dataset/reports/<category>_quality_report.json
    report_file = report_dir / f"{category}_quality_report.json"
    report_data = {
        "category": category,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_samples_reviewed": stats["total"],
        "accepted_samples": stats["accepted"],
        "improved_samples": stats["improved"],
        "rejected_samples": stats["rejected"],
        "duplicate_samples": stats["duplicates"],
        "average_original_score": stats["avg_original_score"],
        "average_final_score": stats["avg_final_score"],
        "samples": sample_reports
    }

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print("\n" + "-" * 75)
    print(f"SUMMARY FOR {input_file.name}:")
    print(f"  Total Processed:         {stats['total']}")
    print(f"  Accepted:                {stats['accepted']} (Direct: {stats['accepted'] - stats['improved']}, Improved: {stats['improved']})")
    print(f"  Rejected:                {stats['rejected']} (Duplicates: {stats['duplicates']})")
    print(f"  Avg Original Score:      {stats['avg_original_score']}/10.0")
    print(f"  Avg Final Score:         {stats['avg_final_score']}/10.0")
    print(f"  Cleaned Dataset:         {output_file}")
    print(f"  Quality Tracking Report: {report_file}")
    print("-" * 75)

    return stats

def main():
    parser = argparse.ArgumentParser(description="CyberQwen-AI: Dataset Quality Improvement via Google Gemini")
    parser.add_argument("--input", type=Path, default=None,
                        help="Path to single input JSONL file (e.g. dataset/generated/crypto.jsonl)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Path to single output JSONL file (e.g. dataset/cleaned/crypto.jsonl)")
    parser.add_argument("--input-dir", type=Path, default=Path("dataset/generated"),
                        help="Directory containing generated JSONL files (default: dataset/generated)")
    parser.add_argument("--output-dir", type=Path, default=Path("dataset/cleaned"),
                        help="Directory to save cleaned JSONL files (default: dataset/cleaned)")
    parser.add_argument("--report-dir", type=Path, default=Path("dataset/reports"),
                        help="Directory to save quality reports (default: dataset/reports)")
    parser.add_argument("--min-score", type=float, default=7.0,
                        help="Minimum Gemini quality score to accept an example (default: 7.0)")
    parser.add_argument("--no-auto-improve", action="store_true",
                        help="Disable automatic Gemini rewriting of borderline samples")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Limit number of samples processed per file (useful for testing)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Delay in seconds between API calls for rate limiting (default: 1.0)")
    args = parser.parse_args()

    print("\n" + "=" * 75)
    print("CYBERQWEN-AI: GEMINI DATASET QUALITY IMPROVEMENT PIPELINE")
    print("=" * 75)

    # Step 1: Pre-flight Gemini Connection Check
    connection_ok = test_gemini_connection()
    if not connection_ok:
        print("\n[!] FATAL: Gemini API connection test failed. Please verify your GEMINI_API_KEY in .env.")
        sys.exit(1)

    print("-" * 75)

    seen_hashes = set()

    # Mode A: Single file processing
    if args.input:
        output_path = args.output or (args.output_dir / args.input.name)
        process_file(
            input_file=args.input,
            output_file=output_path,
            report_dir=args.report_dir,
            min_score=args.min_score,
            auto_improve=not args.no_auto_improve,
            max_samples=args.max_samples,
            delay=args.delay,
            seen_hashes=seen_hashes
        )
    # Mode B: Directory batch processing
    else:
        if not args.input_dir.exists():
            print(f"[!] ERROR: Input directory not found: {args.input_dir}")
            sys.exit(1)

        jsonl_files = sorted(args.input_dir.glob("*.jsonl"))
        if not jsonl_files:
            print(f"[!] No .jsonl files found in {args.input_dir}")
            sys.exit(0)

        print(f"[*] Found {len(jsonl_files)} dataset files to process in {args.input_dir}:")
        for f in jsonl_files:
            print(f"  - {f.name}")

        grand_stats = {"total": 0, "accepted": 0, "improved": 0, "rejected": 0, "duplicates": 0, "scores": []}

        for jsonl_file in jsonl_files:
            out_file = args.output_dir / jsonl_file.name
            stats = process_file(
                input_file=jsonl_file,
                output_file=out_file,
                report_dir=args.report_dir,
                min_score=args.min_score,
                auto_improve=not args.no_auto_improve,
                max_samples=args.max_samples,
                delay=args.delay,
                seen_hashes=seen_hashes
            )
            for k in ["total", "accepted", "improved", "rejected", "duplicates"]:
                grand_stats[k] += stats.get(k, 0)
            grand_stats["scores"].extend(stats.get("final_scores", []))

        avg_grand_score = sum(grand_stats["scores"]) / len(grand_stats["scores"]) if grand_stats["scores"] else 0.0
        print("\n" + "=" * 75)
        print("OVERALL DATASET IMPROVEMENT SUMMARY")
        print("=" * 75)
        print(f"Files Processed:   {len(jsonl_files)}")
        print(f"Total Examples:    {grand_stats['total']}")
        print(f"Accepted:          {grand_stats['accepted']} (Improved: {grand_stats['improved']})")
        print(f"Rejected:          {grand_stats['rejected']} (Duplicates: {grand_stats['duplicates']})")
        print(f"Average Final Quality: {avg_grand_score:.2f}/10.0")
        print(f"Cleaned Directory: {args.output_dir}")
        print(f"Reports Directory: {args.report_dir}")
        print("=" * 75 + "\n")

if __name__ == "__main__":
    main()
