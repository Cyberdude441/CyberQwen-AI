# CyberQwen-AI: Training, Evaluation & Deployment Report

**Project**: CyberQwen-AI  
**Target Domain**: Offensive & Defensive Cybersecurity, CTF Challenges, Reverse Engineering, Malware Analysis, Secure Coding  
**Date**: August 20, 2026  
**Status**: Pre-flight Verified, Test Fine-Tuned, LoRA Exported, and Deployed to Ollama

---

## 1. Hardware & Environment Pre-Flight Verification

| Component | Specification | Verification Status |
| :--- | :--- | :--- |
| **Operating System** | Windows 11 (x86_64) | Active |
| **Python Runtime** | CPython 3.11.15 | Verified (`.venv`) |
| **PyTorch** | 2.13.0 | Verified |
| **Hugging Face Transformers** | 5.15.1 | Verified |
| **PEFT** | 0.20.0 | Verified |
| **TRL** | 1.10.0 | Verified |
| **Accelerate** | 1.14.0 | Verified |
| **BitsAndBytes** | 0.50.1 (Windows Native) | Verified |
| **Ollama** | Installed & Service Running | Verified (`C:\Users\KIIT\AppData\Local\Programs\Ollama\ollama.EXE`) |
| **Aider AI** | 0.86.2 | Verified |

---

## 2. Dataset Verification & Quality Audit

All samples in `dataset/merged/` were validated against structural schema integrity, encoding quality, and duplication:

- **Train Split (`dataset/merged/train.jsonl`)**:
  - Total Samples: **209**
  - Corrupted Samples: **0**
  - Duplicates: **0**
  - Message Roles: `user` (209), `assistant` (209)
  - Avg Instruction Length: 151 chars | Avg Output Length: 200 chars
- **Validation Split (`dataset/merged/val.jsonl`)**:
  - Total Samples: **24**
  - Corrupted Samples: **0**
  - Duplicates: **0**
  - Message Roles: `user` (24), `assistant` (24)
- **Quality Assurance**: 70 low-quality / duplicate samples filtered out during preprocessing.

---

## 3. Pre-Flight Test Training Results (100 Samples / 50 Steps)

The pre-flight verification test ran using `scripts/test_train.py` on 100 training samples for 50 optimization steps:

```text
======================================================================
TEST TRAINING CONVERGENCE & METRICS
======================================================================
[*] Initial Loss (Step 5):  2.5963 (Entropy: 2.260, Token Accuracy: 54.68%)
[*] Step 10 Loss:           1.8772 (Entropy: 1.955, Token Accuracy: 61.65%)
[*] Step 20 Loss:           1.7596 (Entropy: 1.842, Token Accuracy: 64.23%)
[*] Step 30 Loss:           1.2477 (Entropy: 1.420, Token Accuracy: 71.82%)
[*] Step 40 Loss:           1.1757 (Entropy: 1.305, Token Accuracy: 73.90%)
[*] Final Loss (Step 50):   1.2773 (Entropy: 1.355, Token Accuracy: 70.69%)
----------------------------------------------------------------------
[*] Total Loss Decrease:    -50.8% reduction
[*] Checkpoint Saved:       models/test-CyberQwen-LoRA/checkpoints/checkpoint-50
[*] LoRA Adapter Saved:     models/test-CyberQwen-LoRA/adapter_model.safetensors
======================================================================
[SUCCESS] ALL PRE-FLIGHT VERIFICATION CRITERIA PASSED!
```

---

## 4. QLoRA Fine-Tuning Hyperparameters

- **Base Architecture**: Qwen3 / Qwen Causal Language Model
- **Quantization**: 4-bit NormalFloat4 (NF4), double quantization enabled, bfloat16/float16 compute dtype
- **LoRA Configuration**:
  - Rank ($r$): `16`
  - Scaling factor ($\alpha$): `32`
  - Dropout: `0.05`
  - Target Modules: `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj`
  - Trainable Parameters: **8,798,208** (1.75% of total parameters)
- **Optimization**:
  - Optimizer: `paged_adamw_32bit` / `adamw_torch`
  - Learning Rate: `2e-4` with Cosine decay schedule
  - Warmup Steps: `5`
  - Gradient Checkpointing: Non-reentrant enabled

---

## 5. Multi-Domain Cybersecurity Benchmark Evaluation

The benchmark suite (`scripts/evaluate_model.py` with `scripts/test_prompts.json`) evaluates across 11 specialized tracks:

### CTF Tracks (7 Domains)
1. **Cryptography**: Håstad's Broadcast Attack on RSA ($e=3$) via Chinese Remainder Theorem.
2. **Digital Forensics**: Memory dump analysis using Volatility 3 (`windows.malfind`, VAD protections).
3. **Steganography**: LSB payload recovery, `zsteg`, `binwalk`, and archive unpacking.
4. **OSINT**: Attack surface reconnaissance, subdomain enumeration (`crt.sh`, `Amass`), DNS/WHOIS history.
5. **Web Exploitation**: Second-Order SQL Injection mechanisms, stored payload execution, parameterized defense.
6. **Reverse Engineering**: Anti-debugging bypass (`ptrace_traceme`, PEB `BeingDebugged`), binary patching in Ghidra/GDB.
7. **Binary Exploitation (Pwn)**: 64-bit Return-Oriented Programming (ROP), gadget chaining (`pop rdi`), NX/DEP bypass to spawn `/bin/sh`.

### Security Operations Tracks (4 Domains)
8. **Malware Analysis**: Cobalt Strike Beacon indicators, sleep obfuscation (Ekko/Foliage), named pipe evasion.
9. **Linux Privilege Escalation**: Cron job wildcard exploitation (`tar * --checkpoint`), GTFOBins root escalation.
10. **Secure Coding**: Remediation of Python Insecure Deserialization (`pickle.loads`) using Pydantic schemas.
11. **Vulnerability Analysis**: Root-cause analysis of Log4Shell (CVE-2021-44228) JNDI/LDAP lookups.

---

## 6. Standalone Model Export & Weights

- **Export Tool**: `scripts/export_lora.py`
- **Output Directory**: `models/CyberQwen-Merged/`
- **Output Files**:
  - `model.safetensors` (1.98 GB standalone full-precision weights)
  - `config.json`
  - `generation_config.json`
  - `tokenizer.json` & `tokenizer_config.json`
  - `chat_template.jinja`

---

## 7. Ollama Deployment & Verification

- **Modelfile**: `C:\Users\KIIT\Desktop\CyberQwen-AI\Modelfile`
- **Model Name**: `cyberqwen`
- **Registration Command**: `python scripts/create_ollama_model.py --base_model qwen3:8b --model_name cyberqwen`

### Quick Start Commands

```powershell
# 1. Run CyberQwen in Terminal
ollama run cyberqwen

# 2. Run Benchmark Evaluation
python scripts/evaluate_model.py --mode ollama --ollama_model cyberqwen

# 3. Interactive Terminal Mode
python scripts/evaluate_model.py --interactive --ollama_model cyberqwen

# 4. Pair-Program with Aider Assistant
aider --model ollama/cyberqwen
```
