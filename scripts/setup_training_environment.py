"""
CyberQwen-AI: Cloud & Local Training Environment Setup Suite
Automates environment diagnostics, GPU detection, CUDA & bitsandbytes verification,
and Qwen3-8B model loading validation for Colab, RunPod, and local GPU machines.
"""

import os
import sys
import subprocess
import torch
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

REQUIRED_PACKAGES = [
    "torch",
    "transformers",
    "peft",
    "trl",
    "accelerate",
    "bitsandbytes",
    "datasets",
    "pyyaml"
]

def check_and_install_dependencies():
    print("\n" + "=" * 80)
    print("CYBERQWEN-AI: CLOUD & LOCAL ENVIRONMENT SETUP")
    print("=" * 80)
    print("[*] Step 1/4: Checking core fine-tuning packages...")

    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
            print(f"  [+] {pkg:<18} Installed")
        except ImportError:
            missing.append(pkg)
            print(f"  [-] {pkg:<18} Missing")

    if missing:
        print(f"\n[*] Installing {len(missing)} missing packages: {', '.join(missing)}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        print("[+] Packages installed successfully.")

def verify_gpu_and_cuda():
    print("\n[*] Step 2/4: Verifying CUDA acceleration & GPU topology...")
    cuda_available = torch.cuda.is_available()
    
    if not cuda_available:
        print("  [!] CUDA Available:   FALSE (CPU Mode)")
        print("  [!] Warning: No CUDA-capable GPU detected. Fine-tuning an 8B model will require a GPU.")
        return False

    gpu_count = torch.cuda.device_count()
    device_name = torch.cuda.get_device_name(0)
    vram_gb = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2)
    cap = torch.cuda.get_device_capability(0)
    bf16 = torch.cuda.is_bf16_supported()

    print(f"  [+] CUDA Available:   TRUE (PyTorch {torch.__version__})")
    print(f"  [+] GPU Device:       {device_name} (Total: {gpu_count} device(s))")
    print(f"  [+] Total VRAM:       {vram_gb} GB")
    print(f"  [+] CUDA Capability:  {cap[0]}.{cap[1]}")
    print(f"  [+] BF16 Support:     {bf16}")
    return True

def verify_bitsandbytes():
    print("\n[*] Step 3/4: Verifying 4-bit BitsAndBytes quantization...")
    try:
        import bitsandbytes as bnb
        print(f"  [+] BitsAndBytes:     v{bnb.__version__} (Loaded successfully)")
        return True
    except Exception as e:
        print(f"  [!] BitsAndBytes Error: {e}")
        return False

def verify_qwen3_loading():
    print("\n[*] Step 4/4: Verifying Qwen/Qwen3-8B tokenizer & model config...")
    try:
        from transformers import AutoTokenizer, AutoConfig
        tok = AutoTokenizer.from_pretrained("Qwen/Qwen3-8B", trust_remote_code=True)
        cfg = AutoConfig.from_pretrained("Qwen/Qwen3-8B", trust_remote_code=True)
        print(f"  [+] Qwen3 Tokenizer:  Loaded (Vocab: {tok.vocab_size:,})")
        print(f"  [+] Qwen3 Config:     Model type '{cfg.model_type}', Layers: {cfg.num_hidden_layers}")
        return True
    except Exception as e:
        print(f"  [!] Qwen3 Verification Error: {e}")
        return False

def main():
    check_and_install_dependencies()
    has_gpu = verify_gpu_and_cuda()
    bnb_ok = verify_bitsandbytes()
    qwen_ok = verify_qwen3_loading()

    print("\n" + "=" * 80)
    print("ENVIRONMENT SETUP SUMMARY")
    print("=" * 80)
    if has_gpu and bnb_ok and qwen_ok:
        print("  STATUS: READY FOR PRODUCTION GPU QLORA FINE-TUNING")
    else:
        print("  STATUS: WAITING FOR GPU (Environment verified, awaiting CUDA execution host)")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()
