"""
CyberQwen-AI: Comprehensive Benchmark and Evaluation Suite
Evaluates and compares Base Model vs CyberQwen-LoRA across 11 Cybersecurity Tracks:
CTF Tracks:
1. Cryptography
2. Digital Forensics
3. Steganography
4. OSINT
5. Web Exploitation
6. Reverse Engineering
7. Binary Exploitation (Pwn)

Security Operations:
8. Malware Analysis
9. Linux Privilege Escalation
10. Secure Coding
11. Vulnerability Analysis
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SYSTEM_PROMPT = """You are CyberQwen AI.
You specialize in:
- CTF solving
- Digital forensics
- OSINT
- Malware analysis
- Reverse engineering
- Web security
- Secure coding
- Vulnerability analysis
- Linux security"""

def evaluate_ollama(model_name: str, prompts: List[Dict]) -> List[Dict]:
    """Runs evaluation using Ollama."""
    import ollama
    print(f"\n[*] Evaluating Ollama Model: '{model_name}'...")
    results = []
    
    for idx, item in enumerate(prompts, 1):
        domain = item.get("domain", item.get("category", "General"))
        track = item.get("track", "Security")
        prompt = item["prompt"]
        expected_kws = item.get("expected_keywords", [])
        
        print(f"  [{idx:>2}/{len(prompts)}] [{track}] {domain:<26} ... ", end="", flush=True)
        start = time.time()
        
        try:
            res = ollama.chat(
                model=model_name,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ]
            )
            elapsed = time.time() - start
            text = res["message"]["content"]
        except Exception as e:
            elapsed = time.time() - start
            text = f"[ERROR] Ollama call failed: {e}"

        matches = [kw for kw in expected_kws if kw.lower() in text.lower()]
        score = (len(matches) / len(expected_kws) * 100) if expected_kws else 100.0

        print(f"Done ({elapsed:.2f}s) | Score: {score:>5.1f}% ({len(matches)}/{len(expected_kws)} kws)")
        
        results.append({
            "track": track,
            "category": item.get("category", "general"),
            "domain": domain,
            "prompt": prompt,
            "response": text,
            "latency_seconds": round(elapsed, 2),
            "matched_keywords": matches,
            "expected_keywords": expected_kws,
            "keyword_coverage_pct": round(score, 1)
        })

    return results

def evaluate_hf(base_model_id: str, lora_path: str = None, prompts: List[Dict] = None) -> List[Dict]:
    """Runs evaluation using Transformers + PEFT."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel

    tag = f"{base_model_id} + LoRA ({lora_path})" if lora_path else f"Base Model ({base_model_id})"
    print(f"\n[*] Loading HF Model for evaluation: {tag}...")

    tokenizer = AutoTokenizer.from_pretrained(base_model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    cuda_available = torch.cuda.is_available()
    device = "cuda" if cuda_available else "cpu"
    dtype = torch.bfloat16 if (cuda_available and torch.cuda.is_bf16_supported()) else (torch.float16 if cuda_available else torch.float32)

    model = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        dtype=dtype,
        device_map="auto" if cuda_available else "cpu",
        trust_remote_code=True
    )

    if lora_path and Path(lora_path).exists():
        print(f"[*] Attaching LoRA weights from: {lora_path}")
        model = PeftModel.from_pretrained(model, str(lora_path))

    model.eval()
    results = []

    for idx, item in enumerate(prompts, 1):
        domain = item.get("domain", item.get("category", "General"))
        track = item.get("track", "Security")
        prompt = item["prompt"]
        expected_kws = item.get("expected_keywords", [])

        print(f"  [{idx:>2}/{len(prompts)}] [{track}] {domain:<26} ... ", end="", flush=True)
        
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        if hasattr(tokenizer, "apply_chat_template") and tokenizer.chat_template:
            formatted = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        else:
            formatted = f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"

        inputs = tokenizer(formatted, return_tensors="pt").to(device)
        start = time.time()

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.7,
                top_p=0.9,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id
            )

        elapsed = time.time() - start
        gen_tokens = outputs[0][inputs.input_ids.shape[1]:]
        text = tokenizer.decode(gen_tokens, skip_special_tokens=True)

        matches = [kw for kw in expected_kws if kw.lower() in text.lower()]
        score = (len(matches) / len(expected_kws) * 100) if expected_kws else 100.0

        print(f"Done ({elapsed:.2f}s) | Score: {score:>5.1f}% ({len(matches)}/{len(expected_kws)} kws)")

        results.append({
            "track": track,
            "category": item.get("category", "general"),
            "domain": domain,
            "prompt": prompt,
            "response": text,
            "latency_seconds": round(elapsed, 2),
            "matched_keywords": matches,
            "expected_keywords": expected_kws,
            "keyword_coverage_pct": round(score, 1)
        })

    return results

def run_comparison_benchmark(
    base_model_id: str,
    lora_path: str,
    prompts: List[Dict],
    output_report_path: Path
):
    """Runs comparative evaluation between Base Model and CyberQwen-LoRA."""
    print("\n" + "=" * 80)
    print("CYBERQWEN-AI COMPARATIVE BENCHMARK: BASE MODEL VS CYBERQWEN-LORA")
    print("=" * 80)

    # 1. Evaluate Base Model
    print("\n--- PHASE 1: EVALUATING BASE MODEL ---")
    base_results = evaluate_hf(base_model_id, lora_path=None, prompts=prompts)

    # 2. Evaluate LoRA Fine-Tuned Model
    print("\n--- PHASE 2: EVALUATING CYBERQWEN-LORA ---")
    lora_results = evaluate_hf(base_model_id, lora_path=lora_path, prompts=prompts)

    # 3. Compile Comparison Summary
    print("\n" + "=" * 85)
    print(f"{'TRACK':<10} {'DOMAIN':<28} {'BASE SCORE':<14} {'CYBERQWEN-LORA':<18} {'IMPROVEMENT'}")
    print("=" * 85)

    comparison_data = []
    base_total = 0.0
    lora_total = 0.0

    for b, l in zip(base_results, lora_results):
        domain = b["domain"]
        track = b.get("track", "Security")
        b_score = b["keyword_coverage_pct"]
        l_score = l["keyword_coverage_pct"]
        diff = l_score - b_score
        diff_str = f"+{diff:.1f}%" if diff > 0 else f"{diff:.1f}%"
        
        base_total += b_score
        lora_total += l_score

        print(f"{track:<10} {domain:<28} {b_score:>6.1f}%        {l_score:>6.1f}%             {diff_str}")

        comparison_data.append({
            "track": track,
            "domain": domain,
            "base_score_pct": b_score,
            "lora_score_pct": l_score,
            "improvement_pct": round(diff, 1),
            "base_latency_s": b["latency_seconds"],
            "lora_latency_s": l["latency_seconds"],
            "prompt": b["prompt"],
            "base_response": b["response"][:300] + "...",
            "lora_response": l["response"][:300] + "..."
        })

    avg_base = base_total / len(base_results) if base_results else 0.0
    avg_lora = lora_total / len(lora_results) if lora_results else 0.0
    avg_diff = avg_lora - avg_base

    print("-" * 85)
    print(f"{'OVERALL':<10} {'AVERAGE BENCHMARK SCORE':<28} {avg_base:>6.1f}%        {avg_lora:>6.1f}%             {'+' if avg_diff > 0 else ''}{avg_diff:.1f}%")
    print("=" * 85)

    # Save to models/evaluation_report.json
    output_report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "metadata": {
            "title": "CyberQwen-AI Comprehensive Benchmark Report",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "base_model": base_model_id,
            "lora_adapter": lora_path,
            "total_domains_tested": len(prompts)
        },
        "summary": {
            "base_model_average_pct": round(avg_base, 2),
            "cyberqwen_lora_average_pct": round(avg_lora, 2),
            "delta_improvement_pct": round(avg_diff, 2)
        },
        "domain_comparison": comparison_data
    }

    with open(output_report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Full comparison report saved to: {output_report_path}")
    return report

def main():
    parser = argparse.ArgumentParser(description="CyberQwen-AI: Evaluation and Benchmarking Suite")
    parser.add_argument("--mode", choices=["compare", "ollama", "hf"], default="compare",
                        help="Mode: 'compare' (Base vs LoRA), 'ollama', or 'hf'")
    parser.add_argument("--base_model", type=str, default="Qwen/Qwen3-8B",
                        help="Base model ID (default: Qwen/Qwen3-8B)")
    parser.add_argument("--lora_path", type=str, default="models/CyberQwen-LoRA",
                        help="Path to LoRA weights (default: models/CyberQwen-LoRA)")
    parser.add_argument("--ollama_model", type=str, default="cyberqwen",
                        help="Ollama model name")
    parser.add_argument("--test_file", type=Path, default=Path("scripts/test_prompts.json"),
                        help="Test prompts benchmark file")
    parser.add_argument("--output_report", type=Path, default=Path("models/evaluation_report.json"),
                        help="Output JSON evaluation report path")
    args = parser.parse_args()

    # Load prompts
    if not args.test_file.exists():
        raise FileNotFoundError(f"Benchmark file not found: {args.test_file}")
    
    with open(args.test_file, "r", encoding="utf-8") as f:
        prompts = json.load(f)

    if args.mode == "compare":
        # Fallback to test adapter if full adapter is in progress
        lora_target = args.lora_path
        if not Path(lora_target).exists() and Path("models/test-CyberQwen-LoRA").exists():
            lora_target = "models/test-CyberQwen-LoRA"
        run_comparison_benchmark(args.base_model, lora_target, prompts, args.output_report)
    elif args.mode == "ollama":
        results = evaluate_ollama(args.ollama_model, prompts)
        args.output_report.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_report, "w", encoding="utf-8") as f:
            json.dump({"mode": "ollama", "results": results}, f, indent=2)
        print(f"\n[+] Saved to {args.output_report}")
    elif args.mode == "hf":
        results = evaluate_hf(args.base_model, args.lora_path, prompts)
        args.output_report.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_report, "w", encoding="utf-8") as f:
            json.dump({"mode": "hf", "results": results}, f, indent=2)
        print(f"\n[+] Saved to {args.output_report}")

if __name__ == "__main__":
    main()
