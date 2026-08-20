# CyberQwen-AI: Production QLoRA Training Configuration Report

**Document Version**: 2.0  
**Generated**: 2026-08-20  
**Base Architecture**: `Qwen/Qwen3-8B`  
**Fine-Tuning Objective**: Specialized Cybersecurity Reasoning, CTF Solving, CVE Analysis, and Defensive Hardening  

---

## 1. Model & Tokenizer Architecture

| Component | Parameter / Specification | Status |
| :--- | :--- | :--- |
| **Base Model Identifier** | `Qwen/Qwen3-8B` | Verified & Active |
| **Tokenizer** | `Qwen/Qwen3-8B` (Qwen2/3 Tokenizer) | Verified |
| **Chat Template Format** | Standard Qwen ChatML (`<|im_start|>`, `<|im_end|>`) | Fully Compatible |
| **Vocabulary Size** | 151,643 tokens | Loaded |
| **Sequence Length Bound** | 256 (expandable to 512 / 1024 / 2048) | Configured |

---

## 2. Quantization & LoRA Fine-Tuning Parameters

| Hyperparameter | Configuration | Technical Rationale |
| :--- | :--- | :--- |
| **Quantization Scheme** | 4-Bit NF4 (`BitsAndBytesConfig`) | Compresses 8B weights from 16 GB down to ~5.5 GB VRAM |
| **Compute Dtype** | `bfloat16` / `float16` | Accelerated mixed-precision gradient computation |
| **Double Quantization** | `True` | Additional secondary quantization of quantization constants |
| **LoRA Rank ($r$)** | `16` | Optimal capacity for multi-domain cybersecurity reasoning |
| **LoRA Alpha ($\alpha$)** | `32` | Scaling factor ($\alpha / r = 2.0$) |
| **LoRA Dropout** | `0.05` | Prevents over-fitting on specific exploit syntax |
| **Target Projections** | `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj` | Full-coverage attention and MLP adaptors |
| **Trainable Parameters** | ~2.4M - 8.8M parameters (~0.15% - 1.75%) | Extreme parameter efficiency |

---

## 3. Dataset Configuration & Curricular Balance

| Dataset Split | File Path | Sample Count | Curriculum Breakdown |
| :--- | :--- | :---: | :--- |
| **Train Set** | `dataset/final/train_v2.jsonl` | **2,250** | 10% Beginner, 50% Intermediate, 30% Advanced, 10% Expert |
| **Validation Set** | `dataset/final/validation_v2.jsonl` | **250** | 10% Beginner, 50% Intermediate, 30% Advanced, 10% Expert |
| **Total Examples** | `dataset/final/` | **2,500** | **100% Disjoint (0 Data Leakage)** |

---

## 4. Hyperparameters & Optimizer

- **Epochs**: 3
- **Per-Device Batch Size**: 2
- **Gradient Accumulation Steps**: 8
- **Effective Global Batch Size**: $2 \times 8 = 16$
- **Learning Rate**: $2 \times 10^{-4}$ (`2e-4`)
- **Learning Rate Scheduler**: Cosine Annealing with 5 warmup steps
- **Weight Decay**: 0.01
- **Optimizer**: `paged_adamw_32bit` (CUDA) / `adamw_torch` (CPU)

---

## 5. Hardware Requirements & VRAM Budget

| Resource Category | Memory Footprint (Estimated) |
| :--- | :---: |
| **4-bit Quantized Base Model (`Qwen3-8B`)** | ~5.2 – 5.5 GB VRAM |
| **LoRA Adapters & Optimizer Gradients** | ~1.8 – 2.0 GB VRAM |
| **Activation Cache (Batch=2, SeqLen=256)** | ~1.0 – 1.2 GB VRAM |
| **Total Peak VRAM Footprint** | **~8.2 – 8.8 GB VRAM** |

### Adaptive Hardware Recommendations:
- **Recommended GPU**: RTX 3060 (12GB), RTX 4060 Ti (16GB), RTX 3080/3090/4090 (24GB), A10G, T4, or A100.
- **For 8GB VRAM GPUs (e.g. RTX 3070 / RTX 4060 8GB)**:
  Run with reduced per-device batch size and increased gradient accumulation:
  ```powershell
  python scripts/train_qlora.py `
    --model_id Qwen/Qwen3-8B `
    --train_path dataset/final/train_v2.jsonl `
    --val_path dataset/final/validation_v2.jsonl `
    --batch_size 1 `
    --grad_accum 16 `
    --max_length 256
  ```

---

## 6. Execution Command

```powershell
.\.venv\Scripts\Activate.ps1

python scripts/train_qlora.py `
  --model_id Qwen/Qwen3-8B `
  --train_path dataset/final/train_v2.jsonl `
  --val_path dataset/final/validation_v2.jsonl `
  --epochs 3 `
  --batch_size 2 `
  --grad_accum 8 `
  --lr 2e-4
```
