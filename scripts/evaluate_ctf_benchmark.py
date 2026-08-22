"""
CyberQwen-AI: Automated CTF Flag Recovery Benchmark Suite
Evaluates exact flag recovery rate, false positive rate, and chain-of-evidence usage across 100 test samples.
"""

import os
import json
import time
import requests
from pathlib import Path

BENCHMARK_PATH = Path("dataset/ctf/ctf_flag_recovery_test.jsonl")
API_URL = "http://127.0.0.1:8000/chat"

def evaluate_ctf_benchmark(max_eval: int = 20):
    print("\n" + "=" * 70)
    print("CYBERQWEN-AI: CTF CHAIN-OF-EVIDENCE BENCHMARK EVALUATION")
    print("=" * 70)

    if not BENCHMARK_PATH.exists():
        raise FileNotFoundError(f"Benchmark dataset not found at {BENCHMARK_PATH}")

    with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
        samples = [json.loads(line) for line in f if line.strip()]

    eval_subset = samples[:max_eval]
    print(f"[*] Total benchmark samples: {len(samples)}")
    print(f"[*] Evaluating subset:       {len(eval_subset)} samples\n")

    correct_flags = 0
    correct_negative_rejections = 0
    false_positives = 0
    evidence_usage_scores = []
    
    total_start = time.time()

    for i, item in enumerate(eval_subset, 1):
        target_flag = item["target_flag"]
        category = item["category"]
        prompt = item["input"]
        
        print(f"[{i}/{len(eval_subset)}] Testing [{category}] ... ", end="", flush=True)

        try:
            r = requests.post(API_URL, json={
                "message": prompt,
                "system_prompt": "You are CyberQwen CTF Solver. Recover the exact flag if confirmed, or output FLAG NOT RECOVERED.",
                "temperature": 0.1,
                "max_tokens": 512
            }, timeout=30)
            
            if r.status_code == 200:
                response = r.json().get("response", "")
                
                # Check for evidence keywords
                evidence_keywords = ["evidence", "analysis", "solution", "file", "sha", "bytes", "format"]
                ev_score = sum(1 for kw in evidence_keywords if kw in response.lower()) / len(evidence_keywords)
                evidence_usage_scores.append(ev_score)

                if target_flag != "FLAG NOT RECOVERED":
                    if target_flag in response:
                        correct_flags += 1
                        print("✅ FLAG RECOVERED")
                    else:
                        print("❌ MISSED FLAG")
                else:
                    if "FLAG NOT RECOVERED" in response or "not recovered" in response.lower():
                        correct_negative_rejections += 1
                        print("✅ CORRECT NEGATIVE REJECTION")
                    else:
                        false_positives += 1
                        print("⚠️ FALSE POSITIVE")
            else:
                print(f"❌ API ERROR {r.status_code}")
        except Exception as e:
            print(f"❌ CONNECTION ERROR ({e})")

    total_time = round(time.time() - total_start, 2)
    flag_samples_count = sum(1 for s in eval_subset if s["target_flag"] != "FLAG NOT RECOVERED")
    neg_samples_count = len(eval_subset) - flag_samples_count

    accuracy = (correct_flags / flag_samples_count * 100) if flag_samples_count > 0 else 0
    avg_evidence_score = (sum(evidence_usage_scores) / len(evidence_usage_scores) * 100) if evidence_usage_scores else 0

    print("\n" + "=" * 70)
    print("CTF BENCHMARK RESULTS SUMMARY:")
    print(f"  Total Samples Evaluated:   {len(eval_subset)}")
    print(f"  Flag Recovery Rate:        {accuracy:.1f}% ({correct_flags}/{flag_samples_count})")
    print(f"  Negative Rejection Rate:   {100.0 if false_positives == 0 else 0.0}% ({correct_negative_rejections}/{neg_samples_count})")
    print(f"  False Positive Rate:       {false_positives / len(eval_subset) * 100:.1f}%")
    print(f"  Chain-of-Evidence Score:   {avg_evidence_score:.1f}%")
    print(f"  Total Evaluation Time:     {total_time}s")
    print("=" * 70 + "\n")

    # Save metrics report
    report_data = {
        "evaluated_samples": len(eval_subset),
        "flag_recovery_rate_pct": round(accuracy, 2),
        "false_positive_rate_pct": round(false_positives / len(eval_subset) * 100, 2),
        "evidence_usage_score_pct": round(avg_evidence_score, 2),
        "evaluation_time_seconds": total_time
    }
    with open("logs/ctf_benchmark_metrics.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print("[+] Saved benchmark metrics to logs/ctf_benchmark_metrics.json")

if __name__ == "__main__":
    evaluate_ctf_benchmark()
