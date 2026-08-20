"""
CyberQwen-AI: LoRA Weight Merging and Export Tool
Merges fine-tuned LoRA adapters with the base Qwen3 model into a standalone Hugging Face model.
"""

import os
import sys
import torch
import argparse
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def main():
    parser = argparse.ArgumentParser(description="CyberQwen-AI: LoRA Export and Weight Merger")
    parser.add_argument("--base_model", type=str, default="Qwen/Qwen3-8B",
                        help="Base model name or path (default: Qwen/Qwen3-8B)")
    parser.add_argument("--lora_path", type=Path, default=Path("models/CyberQwen-LoRA"),
                        help="Path to trained LoRA adapter (default: models/CyberQwen-LoRA)")
    parser.add_argument("--output_dir", type=Path, default=Path("models/CyberQwen-Merged"),
                        help="Target directory for merged weights (default: models/CyberQwen-Merged)")
    parser.add_argument("--device", type=str, default="auto",
                        help="Device to load model on ('auto', 'cpu', 'cuda')")
    parser.add_argument("--push_to_hub", type=str, default=None,
                        help="Optional Hugging Face repo ID to upload merged model (e.g. username/CyberQwen-Merged)")
    parser.add_argument("--hf_token", type=str, default=None,
                        help="Hugging Face API token for Hub upload")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("CYBERQWEN-AI: LORA MERGE AND EXPORT PIPELINE")
    print("=" * 70)
    print(f"[*] Base Model:       {args.base_model}")
    print(f"[*] LoRA Adapter:     {args.lora_path}")
    print(f"[*] Output Directory: {args.output_dir}")
    print("=" * 70 + "\n")

    if not args.lora_path.exists():
        raise FileNotFoundError(f"LoRA adapter not found at {args.lora_path}! Please run scripts/train_qlora.py first.")

    cuda_available = torch.cuda.is_available()
    dtype = torch.bfloat16 if (cuda_available and torch.cuda.is_bf16_supported()) else (torch.float16 if cuda_available else torch.float32)
    device_map = "auto" if (args.device == "auto" and cuda_available) else (args.device if args.device != "auto" else "cpu")

    print(f"[*] Step 1/4: Loading tokenizer for {args.base_model}...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(args.lora_path, trust_remote_code=True)
    except Exception:
        tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)

    print(f"[*] Step 2/4: Loading base model in full precision ({dtype})...")
    base_model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=dtype,
        device_map=device_map,
        trust_remote_code=True,
        low_cpu_mem_usage=True
    )

    print(f"[*] Step 3/4: Loading LoRA adapter from {args.lora_path}...")
    peft_model = PeftModel.from_pretrained(base_model, str(args.lora_path))

    print("[*] Merging LoRA adapter weights into base model layers...")
    merged_model = peft_model.merge_and_unload()

    print(f"[*] Step 4/4: Saving merged model and tokenizer to {args.output_dir}...")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    merged_model.save_pretrained(args.output_dir, safe_serialization=True)
    tokenizer.save_pretrained(args.output_dir)

    print("\n" + "=" * 70)
    print("[SUCCESS] MODEL MERGED AND SAVED SUCCESSFULLY!")
    print(f"[*] Merged weights path: {args.output_dir}")
    print("=" * 70)

    if args.push_to_hub:
        print(f"\n[*] Uploading merged model to Hugging Face Hub: {args.push_to_hub}...")
        merged_model.push_to_hub(args.push_to_hub, token=args.hf_token)
        tokenizer.push_to_hub(args.push_to_hub, token=args.hf_token)
        print(f"[+] Successfully pushed to https://huggingface.co/{args.push_to_hub}")

if __name__ == "__main__":
    main()
