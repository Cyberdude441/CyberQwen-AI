"""
CyberQwen-AI: Pre-Training Command Generator
Detects current hardware environment and outputs the exact optimal training command.
"""

import os
import sys
import torch
from pathlib import Path

def generate_command():
    cuda_available = torch.cuda.is_available()
    vram_gb = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2) if cuda_available else 0.0
    device_name = torch.cuda.get_device_name(0) if cuda_available else "CPU"

    print("\n" + "=" * 80)
    print("CYBERQWEN-AI: OPTIMAL TRAINING COMMAND GENERATOR")
    print("=" * 80)
    print(f"Detected Hardware: {device_name} ({vram_gb} GB VRAM)")

    if not cuda_available:
        print("\n[!] Status: WAITING FOR GPU")
        print("[*] For cloud / remote training, select one of the profiles below:\n")
        print("--- Google Colab (T4 15GB) ---")
        print("python scripts/train_qlora.py --config configs/colab_t4.yaml\n")
        print("--- Google Colab (L4 24GB) / RunPod RTX 4090 (24GB) ---")
        print("python scripts/train_qlora.py --config configs/colab_l4.yaml\n")
        print("--- RunPod / Lambda A100 (40GB/80GB) ---")
        print("python scripts/train_qlora.py --config configs/a100.yaml\n")
        print("--- Local NVIDIA GPU (12GB+) ---")
        print("python scripts/train_qlora.py --config configs/local_12gb.yaml\n")
        return

    print("\n[+] Status: READY FOR TRAINING")
    if vram_gb >= 35.0:
        cfg = "configs/a100.yaml"
    elif vram_gb >= 20.0:
        cfg = "configs/colab_l4.yaml"
    elif vram_gb >= 11.0:
        cfg = "configs/local_12gb.yaml"
    else:
        cfg = "configs/colab_t4.yaml"

    print(f"[*] Recommended Profile: {cfg}\n")
    print("Command:")
    print(f"python scripts/train_qlora.py --config {cfg}\n")

if __name__ == "__main__":
    generate_command()
