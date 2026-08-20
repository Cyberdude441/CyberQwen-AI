# CyberQwen-AI: Cybersecurity LLM & QLoRA Fine-Tuning Pipeline

CyberQwen-AI is an end-to-end specialized artificial intelligence platform for offensive and defensive cybersecurity operations, CTF challenges, binary reverse engineering, malware analysis, digital forensics, secure coding, and automated AI pair-programming with Aider.

---

## 📁 Project Architecture & Folder Structure

```text
CyberQwen-AI/
├── .env                          # API keys (NVIDIA, Hugging Face, etc.)
├── .venv/                        # Isolated Python 3.11 Virtual Environment
├── Modelfile                     # Ollama configuration and system instructions
├── README.md                     # Complete pipeline documentation
├── requirements.txt              # Standardized dependency specifications
├── ollama_builder.py             # Dataset generation via local Ollama
├── dataset/
│   ├── cleaned/                  # De-duplicated, normalized JSONL samples
│   ├── ctf/                      # CTF challenge datasets
│   ├── generated/                # Category datasets (crypto, forensics, etc.)
│   ├── linux_security/           # Privilege escalation and hardening datasets
│   ├── malware_analysis/         # Malware evasion and signature datasets
│   ├── merged/                   # Training splits (train.jsonl, val.jsonl)
│   ├── reverse_engineering/      # Disassembly and decompilation datasets
│   ├── secure_coding/            # Static analysis and remediation datasets
│   ├── vulnerability_reports/    # CVE and exploitation datasets
│   └── web_security/             # Web application security datasets
├── models/
│   ├── CyberQwen-LoRA/           # Trained 4-bit LoRA adapter weights
│   ├── CyberQwen-Merged/         # Fully merged standalone model weights
│   └── eval_report.json          # Benchmark evaluation outputs
└── scripts/
    ├── clean_dataset.py          # Data normalization and deduplication
    ├── create_ollama_model.py    # Modelfile generation and Ollama model builder
    ├── dataset_validator.py      # Schema and format validator
    ├── evaluate_model.py         # Multi-domain benchmark evaluation suite
    ├── export_lora.py            # LoRA adapter merger and HF exporter
    ├── generate_dataset.py       # Multi-threaded synthetic dataset generator
    ├── merge_dataset.py          # Train/Validation dataset splitter
    ├── qlora_config.yaml         # Training hyperparameter configuration
    ├── test_prompts.json         # Benchmark questions across 6 core domains
    ├── train_qlora.py            # SFTTrainer QLoRA 4-bit training pipeline
    └── validate_dataset.py       # JSONL integrity verification
```

---

## ⚙️ Environment & Installation

### Requirements
- **OS**: Windows 11 / Linux
- **Python**: 3.11 (Required for PyTorch CUDA, bitsandbytes, and precompiled wheels)
- **Package Manager**: `uv` or `pip`
- **Ollama**: Installed and running (`ollama serve`)

### Setup Environment
```powershell
# 1. Navigate to workspace
cd C:\Users\KIIT\Desktop\CyberQwen-AI

# 2. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Verify packages
python -c "import torch, transformers, peft, trl, bitsandbytes, ollama, aider; print('Environment Ready!')"
```

---

## 🛠️ Complete Pipeline Execution

### 1. Dataset Preparation & Preprocessing

The dataset pipeline generates, cleans, and structures training samples into Qwen3 chat format (`messages`).

```powershell
# Step 1A: Clean raw datasets (normalizes text, eliminates low-quality patterns, removes duplicates)
python scripts/clean_dataset.py --categories generated secure_coding

# Step 1B: Merge and split into train (90%) and validation (10%) sets
python scripts/merge_dataset.py --train-ratio 0.9 --seed 42
```

Outputs generated:
- `dataset/merged/train.jsonl`
- `dataset/merged/val.jsonl`

---

### 2. QLoRA 4-Bit Fine-Tuning

The training script `scripts/train_qlora.py` uses `transformers`, `peft`, `bitsandbytes`, and `trl.SFTTrainer`.

#### Key Features:
- **Quantization**: 4-bit NormalFloat4 (NF4) with double quantization and bfloat16 compute dtype.
- **LoRA Configuration**: Rank ($r$) = 16, Alpha ($\alpha$) = 32, Dropout = 0.05.
- **Target Modules**: `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj`.
- **Memory Optimizations**: `prepare_model_for_kbit_training`, gradient checkpointing, `paged_adamw_32bit`.
- **Checkpoint Resumption**: Supports resuming training seamlessly via `--resume_from_checkpoint`.

```powershell
# Launch Production QLoRA Fine-Tuning
python scripts/train_qlora.py `
  --model_id "Qwen/Qwen3-8B" `
  --train_path "dataset/final/train_v2.jsonl" `
  --val_path "dataset/final/validation_v2.jsonl" `
  --output_dir "models/CyberQwen-LoRA" `
  --epochs 3 `
  --batch_size 1 `
  --grad_accum 16 `
  --lr 2e-4
```

Adapter weights and tokenizer are saved to `models/CyberQwen-LoRA/`.

---

### 3. Model Evaluation & Benchmarking

Evaluate CyberQwen across 6 core cybersecurity disciplines:
1. **CTF Solving**: Binary unpacking, Ghidra analysis, flag extraction.
2. **Cryptography**: RSA attacks (Bleichenbacher), padding oracles, OAEP.
3. **Web Security**: SSRF to AWS IMDSv2 exploitation, XSS, SQLi.
4. **Malware Analysis**: Process Hollowing, API evasion, anti-debugging.
5. **Digital Forensics**: Memory dumps, Volatility 3 plugins (`malfind`, `pslist`).
6. **Linux Security**: Privilege escalation, GTFOBins, SUID binaries.

```powershell
# Evaluate via Ollama backend
python scripts/evaluate_model.py --backend ollama --ollama_model cyberqwen

# Evaluate via Hugging Face LoRA weights
python scripts/evaluate_model.py --backend hf --base_model "Qwen/Qwen3-8B" --lora_path "models/CyberQwen-LoRA"

# Interactive cybersecurity assistant mode
python scripts/evaluate_model.py --interactive --ollama_model cyberqwen
```

---

### 4. LoRA Adapter Export & Weight Merging

To convert your trained LoRA adapter into a standalone model (e.g. for GGUF quantization or Hugging Face Hub sharing):

```powershell
# Merge LoRA weights into base model
python scripts/export_lora.py `
  --base_model "Qwen/Qwen3-8B" `
  --lora_path "models/CyberQwen-LoRA" `
  --output_dir "models/CyberQwen-Merged"
```

---

### 5. Ollama Model Creation & Local Deployment

Create and deploy the customized `cyberqwen` model directly into your local Ollama server:

```powershell
# Build Modelfile and register model in Ollama
python scripts/create_ollama_model.py --base_model "qwen3:8b" --model_name "cyberqwen" --test
```

#### Running CyberQwen in Terminal
```powershell
ollama run cyberqwen
```

---

### 6. AI Coding Assistant with Aider

Integrate CyberQwen directly into your development workflow with `aider-chat`:

```powershell
# Pair-program with local CyberQwen via Ollama
aider --model ollama/cyberqwen

# Or pair-program with NVIDIA API / OpenAI-compatible endpoint
$env:OPENAI_API_BASE = "https://integrate.api.nvidia.com/v1"
$env:OPENAI_API_KEY = "nvapi-your-key-here"
aider --model openai/meta/llama-3.3-70b-instruct
```
