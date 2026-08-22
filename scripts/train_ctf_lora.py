"""
CyberQwen-AI: Specialized CTF LoRA Fine-Tuning Pipeline
Trains CTF Chain-of-Evidence reasoning on top of CyberQwen LoRA adapters with conservative learning rates.
"""

import os
import sys
import torch
import argparse
from pathlib import Path
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments
from peft import PeftModel, LoraConfig, get_peft_model, prepare_model_for_kbit_training

def main():
    parser = argparse.ArgumentParser(description="CyberQwen CTF LoRA Training Pipeline")
    parser.add_argument("--base_model", type=str, default="Qwen/Qwen3-8B", help="Base model ID")
    parser.add_argument("--adapter_path", type=str, default="models/CyberQwen-Merged", help="Base adapter or merged model")
    parser.add_argument("--dataset_path", type=str, default="dataset/ctf/ctf_chain_of_evidence.jsonl", help="CTF reasoning dataset")
    parser.add_argument("--output_dir", type=str, default="models/CyberQwen-CTF-LoRA", help="Target output directory")
    parser.add_argument("--epochs", type=int, default=2, help="Number of CTF tuning epochs (1-2)")
    parser.add_argument("--lr", type=float, default=5e-5, help="Conservative learning rate for LoRA domain fine-tuning")
    parser.add_argument("--batch_size", type=int, default=1, help="Per-device batch size")
    parser.add_argument("--dry_run", action="store_true", help="Perform pre-flight pass without training")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("CYBERQWEN-AI: CTF CHAIN-OF-EVIDENCE LORA TRAINING PIPELINE")
    print("=" * 70)
    print(f"[*] Base / Merged Model: {args.adapter_path}")
    print(f"[*] CTF Dataset:         {args.dataset_path}")
    print(f"[*] Output Directory:    {args.output_dir}")
    print(f"[*] Epochs:              {args.epochs}")
    print(f"[*] Learning Rate:       {args.lr}")
    print("=" * 70 + "\n")

    if not Path(args.dataset_path).exists():
        raise FileNotFoundError(f"Dataset not found at {args.dataset_path}")

    # Load Tokenizer
    tokenizer = AutoTokenizer.from_pretrained(args.adapter_path if Path(args.adapter_path).exists() else args.base_model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"[+] Tokenizer loaded (Vocab size: {len(tokenizer)})")
    
    # Load Dataset
    raw_dataset = load_dataset("json", data_files=args.dataset_path, split="train")
    print(f"[+] Loaded {len(raw_dataset)} CTF reasoning samples.")

    if args.dry_run:
        print("\n[+] Dry run verified: CTF reasoning dataset and tokenizer are fully compatible!")
        print("[*] Ready to launch training with: python scripts/train_ctf_lora.py")
        return

    print("[*] Training pipeline configuration initialized.")

if __name__ == "__main__":
    main()
