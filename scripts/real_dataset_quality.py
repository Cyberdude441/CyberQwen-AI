"""
CyberQwen-AI: Real Dataset Quality Filter & Gemini Reviewer
Validates authentic cybersecurity datasets using Google Gemini API.

Scores:
- Cybersecurity Technical Correctness (CVE, Mitre, RFC accuracy)
- Depth & Step-by-Step Reasoning
- Zero Hallucination Risk
- Duplication & Pattern Redundancy
- Training Signal & Actionability
"""

import os
import sys
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent))
from gemini_validator import test_gemini_connection, validate_example, improve_example

load_dotenv()

PROCESSED_DIR = Path("dataset/processed")
REPORTS_DIR = Path("dataset/reports")

def compute_hash(ex: Dict) -> str:
    content = f"{ex.get('instruction', '').strip().lower()}{ex.get('input', '').strip().lower()}{ex.get('output', '').strip().lower()}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def audit_dataset_file(
    input_file: Path,
    output_file: Path,
    report_file: Path,
    min_score: float = 7.0,
    max_samples: Optional[int] = None,
    delay: float = 0.5,
    auto_improve: bool = True
) -> Dict[str, Any]:
    print("\n" + "=" * 75)
    print(f"AUDITING REAL DATASET: {input_file.name}")
    print(f"Input:   {input_file}")
    print(f"Output:  {output_file}")
    print(f"Report:  {report_file}")
    print(f"Min Score: {min_score}/10.0")
    print("=" * 75)

    if not input_file.exists():
        print(f"[!] File not found: {input_file}")
        return {"total": 0, "accepted": 0, "rejected": 0, "duplicates": 0, "avg_score": 0.0}

    raw_items = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    raw_items.append(json.loads(line))
                except Exception:
                    pass

    if max_samples:
        raw_items = raw_items[:max_samples]

    print(f"[*] Loaded {len(raw_items)} samples for quality audit.")

    seen_hashes = set()
    cleaned_items = []
    sample_reports = []
    scores = []
    accepted_count = 0
    improved_count = 0
    rejected_count = 0
    duplicate_count = 0

    output_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.parent.mkdir(parents=True, exist_ok=True)

    for idx, ex in enumerate(raw_items, 1):
        sample_id = f"{input_file.stem}_{idx:04d}"
        inst_preview = ex.get("instruction", "")[:50].replace("\n", " ")
        print(f"\n[{idx:>3}/{len(raw_items)}] [{sample_id}] {inst_preview}...")

        # 1. Duplication Check
        h = compute_hash(ex)
        if h in seen_hashes:
            print("    -> [REJECTED] Duplicate entry detected.")
            duplicate_count += 1
            rejected_count += 1
            sample_reports.append({
                "id": sample_id,
                "category": ex.get("category", "unknown"),
                "score": 0.0,
                "accepted": False,
                "issues": ["Duplicate content detected."],
                "improvements": []
            })
            continue

        # 2. Gemini Evaluation
        eval_res = validate_example(ex)
        score = eval_res.get("score", 5.0)
        quality = eval_res.get("quality", "bad")
        issues = eval_res.get("issues", [])
        suggestion = eval_res.get("suggestion", "")
        diff = eval_res.get("difficulty", ex.get("difficulty", "intermediate"))

        scores.append(score)
        print(f"    -> Gemini Score: {score:>4.1f}/10.0 | Quality: {quality.upper()} | Tier: {diff.upper()}")
        if issues:
            print(f"    -> Issues: {', '.join(issues[:2])}")

        is_accepted = False
        final_ex = ex
        improvements_list = []

        if score >= min_score and quality == "good":
            print("    -> [ACCEPTED] High quality authentic cybersecurity sample.")
            is_accepted = True
            accepted_count += 1
            ex["difficulty"] = diff
            cleaned_items.append(ex)
            seen_hashes.add(h)
            improvements_list.append("Passed validation without modification.")
        elif auto_improve and (score >= 4.0 or issues):
            print("    -> [IMPROVING] Calling Gemini to refine and structure explanations...")
            improved_ex = improve_example(ex, feedback=eval_res)
            re_eval = validate_example(improved_ex)
            re_score = re_eval.get("score", score)
            re_diff = re_eval.get("difficulty", diff)
            print(f"    -> Post-Improvement Score: {re_score:>4.1f}/10.0")

            if re_score >= min_score or re_score > score:
                improved_ex["difficulty"] = re_diff
                improved_ex["category"] = ex.get("category", "cybersecurity")
                improved_ex["source"] = ex.get("source", "verified")
                cleaned_items.append(improved_ex)
                seen_hashes.add(compute_hash(improved_ex))
                is_accepted = True
                accepted_count += 1
                improved_count += 1
                improvements_list.append(f"Elevated reasoning depth and technical mitigation structure ({score:.1f} -> {re_score:.1f})")
                print("    -> [ACCEPTED] Successfully improved sample.")
            else:
                rejected_count += 1
                print("    -> [REJECTED] Sample did not reach quality threshold.")
        else:
            rejected_count += 1
            print(f"    -> [REJECTED] Score ({score:.1f}) below threshold ({min_score}).")

        sample_reports.append({
            "id": sample_id,
            "category": ex.get("category", "unknown"),
            "difficulty": diff,
            "score": round(score, 1),
            "accepted": is_accepted,
            "issues": issues,
            "improvements": improvements_list
        })

        if delay > 0 and idx < len(raw_items):
            time.sleep(delay)

    # Save Cleaned JSONL
    with open(output_file, "w", encoding="utf-8") as f:
        for item in cleaned_items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    avg_score = (sum(scores) / len(scores)) if scores else 0.0

    # Save Quality Report
    report_data = {
        "dataset_file": input_file.name,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_reviewed": len(raw_items),
        "accepted": accepted_count,
        "improved": improved_count,
        "rejected": rejected_count,
        "duplicates": duplicate_count,
        "average_score": round(avg_score, 2),
        "samples": sample_reports
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print("\n" + "-" * 75)
    print(f"SUMMARY FOR {input_file.name}:")
    print(f"  Total Reviewed:  {len(raw_items)}")
    print(f"  Accepted:        {accepted_count} (Improved: {improved_count})")
    print(f"  Rejected:        {rejected_count} (Duplicates: {duplicate_count})")
    print(f"  Average Score:   {avg_score:.2f}/10.0")
    print(f"  Cleaned JSONL:   {output_file}")
    print(f"  Quality Report:  {report_file}")
    print("-" * 75)

    return report_data

def main():
    parser = argparse.ArgumentParser(description="CyberQwen-AI: Real Dataset Quality Filter via Google Gemini")
    parser.add_argument("--input", type=Path, default=Path("dataset/processed/ctf_challenges.jsonl"),
                        help="Input JSONL file")
    parser.add_argument("--output", type=Path, default=None,
                        help="Output cleaned JSONL file")
    parser.add_argument("--report", type=Path, default=None,
                        help="Output report JSON file")
    parser.add_argument("--min-score", type=float, default=7.0,
                        help="Minimum score threshold (default: 7.0)")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Maximum samples to review")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay in seconds between calls")
    args = parser.parse_args()

    out_file = args.output or (PROCESSED_DIR / f"cleaned_{args.input.name}")
    rep_file = args.report or (REPORTS_DIR / f"{args.input.stem}_quality_report.json")

    print("\n" + "=" * 75)
    print("CYBERQWEN-AI: GEMINI REAL DATASET QUALITY AUDIT")
    print("=" * 75)

    if not test_gemini_connection():
        print("[!] FATAL: Gemini API connection test failed. Verify GEMINI_API_KEY in .env.")
        sys.exit(1)

    audit_dataset_file(
        input_file=args.input,
        output_file=out_file,
        report_file=rep_file,
        min_score=args.min_score,
        max_samples=args.max_samples,
        delay=args.delay
    )

if __name__ == "__main__":
    main()
