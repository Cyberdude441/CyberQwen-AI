# CyberQwen-AI: Hardware Selection & Training Deployment Guide

This guide details the hardware specifications, cloud platform options (Google Colab, RunPod, Lambda Labs), and exact setup steps to train **CyberQwen-8B** using QLoRA.

---

## 1. Hardware Requirements Matrix

| Deployment Tier | GPU Model | VRAM | Training Speed | Recommended Profile |
| :--- | :--- | :---: | :---: | :--- |
| **Minimum (Budget)** | NVIDIA T4 / RTX 3060 | 12 – 16 GB | ~45 – 60 mins | `configs/colab_t4.yaml` |
| **Recommended** | NVIDIA L4 / RTX 4090 / A10G | 24 GB | ~20 – 30 mins | `configs/colab_l4.yaml` |
| **High Performance** | NVIDIA A100 / H100 | 40 / 80 GB | ~8 – 12 mins | `configs/a100.yaml` |

---

## 2. Option A: Google Colab Setup (Free T4 or Colab Pro L4/A100)

### Step 1: Open Notebook & Select GPU
1. Go to [Google Colab](https://colab.research.google.com/).
2. Click **Runtime** $\to$ **Change runtime type** $\to$ Select **T4 GPU** (Free) or **A100 / L4 GPU** (Pro).

### Step 2: Clone Repository & Run Environment Setup
```python
# In Colab Code Cell:
!git clone https://github.com/your-username/CyberQwen-AI.git
%cd CyberQwen-AI

!pip install -r requirements.txt
!python scripts/setup_training_environment.py
```

### Step 3: Launch Fine-Tuning
```bash
# For Colab Free T4:
!python scripts/train_qlora.py --config configs/colab_t4.yaml

# For Colab Pro L4 / A100:
!python scripts/train_qlora.py --config configs/colab_l4.yaml
```

---

## 3. Option B: RunPod Cloud Deployment ($0.30 - $0.70 / hr)

### Step 1: Deploy a Pod
1. Log into [RunPod.io](https://runpod.io/).
2. Select **Community Cloud** or **Secure Cloud** $\to$ Choose **1x RTX 4090 (24GB)** or **1x A100 (40GB)**.
3. Select Template: **RunPod PyTorch 2.2.0 (CUDA 12.1)**.

### Step 2: Connect via Web Terminal / SSH
```bash
git clone https://github.com/your-username/CyberQwen-AI.git
cd CyberQwen-AI

pip install -r requirements.txt
python scripts/setup_training_environment.py
```

### Step 3: Start Training
```bash
python scripts/train_qlora.py --config configs/colab_l4.yaml
```

---

## 4. Option C: Local NVIDIA GPU Setup (Windows 11 / Linux)

### Step 1: Install PyTorch with CUDA Support
```powershell
.\.venv\Scripts\Activate.ps1

# Install PyTorch with CUDA 12.1
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
pip install -r requirements.txt
```

### Step 2: Verify GPU Detection
```powershell
python scripts/generate_training_command.py
```

### Step 3: Launch Training
```powershell
python scripts/train_qlora.py --config configs/local_12gb.yaml
```

---

## 5. Pre-Configured Training Profiles (`configs/`)

| Profile File | Batch Size | Grad Accum | Effective Batch | Precision | Max Context |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `configs/local_12gb.yaml` | 2 | 8 | 16 | `bfloat16` | 256 tokens |
| `configs/colab_t4.yaml` | 1 | 16 | 16 | `fp16` | 256 tokens |
| `configs/colab_l4.yaml` | 4 | 4 | 16 | `bfloat16` | 512 tokens |
| `configs/a100.yaml` | 8 | 2 | 16 | `bfloat16` | 1024 tokens |
