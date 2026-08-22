"""
CyberQwen-AI: Master Production QLoRA Fine-Tuning Pipeline
Fine-tunes Qwen3-8B on authentic cybersecurity instruction dataset (v3) with hardware-aware optimization,
VRAM auto-tuning, TRL compatibility guards, and robust step-based checkpointing.
"""

import os
import sys
import time
import yaml
import json
import torch
import argparse
import re
from pathlib import Path
from datasets import load_dataset
import transformers
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainerCallback,
    set_seed
)
import peft
from peft import (
    LoraConfig,
    prepare_model_for_kbit_training,
    TaskType,
    get_peft_model
)
import trl
from trl import SFTTrainer, SFTConfig
import bitsandbytes as bnb

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# --- COMPATIBILITY PATCH: Protect against TRL _patch_chunked_ce_lm_head on functools.partial ---
if hasattr(SFTTrainer, "_patch_chunked_ce_lm_head"):
    _orig_patch = getattr(SFTTrainer, "_patch_chunked_ce_lm_head")
    def _safe_patch(self, *args, **kwargs):
        try:
            return _orig_patch(self, *args, **kwargs)
        except Exception:
            pass
    SFTTrainer._patch_chunked_ce_lm_head = _safe_patch

class TrainingTelemetryMonitor(TrainerCallback):
    """Monitors and displays live training metrics: Epoch, Step, Loss, GPU VRAM, ETA."""
    def __init__(self, total_epochs: int, grad_accum: int):
        self.total_epochs = total_epochs
        self.grad_accum = grad_accum
        self.start_time = time.time()
        self.history = []

    def on_log(self, args, state, control, logs=None, **kwargs):
        if not logs:
            return
            
        current_time = time.time()
        elapsed_total = current_time - self.start_time
        current_step = state.global_step
        max_steps = state.max_steps if state.max_steps > 0 else (state.num_train_epochs * state.num_update_steps_per_epoch)
        
        # Calculate ETA
        if current_step > 0 and max_steps > 0:
            avg_step_time = elapsed_total / current_step
            remaining_steps = max_steps - current_step
            eta_seconds = max(0, remaining_steps * avg_step_time)
            eta_str = f"{int(eta_seconds // 60):02d}m {int(eta_seconds % 60):02d}s"
        else:
            eta_str = "Calculating..."

        train_loss = logs.get("loss", "N/A")
        val_loss = logs.get("eval_loss", "N/A")
        lr = logs.get("learning_rate", 0.0)

        # GPU VRAM Telemetry
        vram_str = "N/A"
        gpu_util = "N/A"
        if torch.cuda.is_available():
            alloc_gb = torch.cuda.memory_allocated() / (1024 ** 3)
            res_gb = torch.cuda.memory_reserved() / (1024 ** 3)
            vram_str = f"{alloc_gb:.2f}GB / {res_gb:.2f}GB"
            gpu_util = f"{round((alloc_gb / res_gb) * 100, 1)}%" if res_gb > 0 else "N/A"

        current_epoch = round(state.epoch, 2) if state.epoch is not None else 0.0
        
        loss_display = f"{train_loss:.4f}" if isinstance(train_loss, (float, int)) else str(train_loss)
        val_display = f"{val_loss:.4f}" if isinstance(val_loss, (float, int)) else str(val_loss)

        print(f"[STEP {current_step:>5}/{max_steps}] Epoch: {current_epoch:>4.2f}/{self.total_epochs} | "
              f"Loss: {loss_display} | Val Loss: {val_display} | LR: {lr:.2e} | VRAM: {vram_str} | ETA: {eta_str}")

        self.history.append({
            "step": current_step,
            "epoch": current_epoch,
            "loss": train_loss if isinstance(train_loss, (float, int)) else None,
            "val_loss": val_loss if isinstance(val_loss, (float, int)) else None,
            "learning_rate": lr,
            "gpu_vram": vram_str,
            "gpu_util": gpu_util,
            "elapsed_seconds": round(elapsed_total, 2)
        })

def format_chat_data(example, tokenizer):
    if "messages" in example and isinstance(example["messages"], list):
        if hasattr(tokenizer, "apply_chat_template") and tokenizer.chat_template:
            return tokenizer.apply_chat_template(example["messages"], tokenize=False, add_generation_prompt=False)
        else:
            text = ""
            for msg in example["messages"]:
                text += f"<|im_start|>{msg.get('role', 'user')}\n{msg.get('content', '')}<|im_end|>\n"
            return text
    return ""

def find_latest_checkpoint(checkpoint_dir: Path) -> Path:
    """Finds latest checkpoint subdirectory sorted by step number."""
    if not checkpoint_dir.exists():
        return None
    ckpts = [p for p in checkpoint_dir.glob("checkpoint-*") if p.is_dir()]
    if not ckpts:
        return None
    def extract_step(p):
        match = re.search(r"checkpoint-(\d+)", p.name)
        return int(match.group(1)) if match else 0
    return max(ckpts, key=extract_step)

def main():
    default_train = Path("dataset/final/train_v3.jsonl") if Path("dataset/final/train_v3.jsonl").exists() else (Path("dataset/final/train_v2.jsonl") if Path("dataset/final/train_v2.jsonl").exists() else Path("dataset/instruction/train.jsonl"))
    default_val = Path("dataset/final/validation_v3.jsonl") if Path("dataset/final/validation_v3.jsonl").exists() else (Path("dataset/final/validation_v2.jsonl") if Path("dataset/final/validation_v2.jsonl").exists() else Path("dataset/instruction/validation.jsonl"))

    parser = argparse.ArgumentParser(description="CyberQwen-AI: Master QLoRA Fine-Tuning Pipeline")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen3-8B",
                        help="Base model ID (default: Qwen/Qwen3-8B)")
    parser.add_argument("--train_path", type=Path, default=default_train,
                        help=f"Train dataset path (default: {default_train})")
    parser.add_argument("--val_path", type=Path, default=default_val,
                        help=f"Validation dataset path (default: {default_val})")
    parser.add_argument("--output_dir", type=Path, default=Path("models/CyberQwen-LoRA"),
                        help="Output directory for LoRA adapter")
    parser.add_argument("--epochs", type=int, default=3,
                        help="Number of training epochs (default: 3)")
    parser.add_argument("--batch_size", type=int, default=None,
                        help="Per-device training batch size (auto-configured by default)")
    parser.add_argument("--grad_accum", type=int, default=None,
                        help="Gradient accumulation steps (auto-configured by default)")
    parser.add_argument("--lr", type=float, default=2e-4,
                        help="Learning rate (default: 2e-4)")
    parser.add_argument("--max_length", type=int, default=256,
                        help="Maximum sequence length (default: 256)")
    parser.add_argument("--precision", type=str, default=None,
                        help="Precision override (fp16, bfloat16, fp32)")
    parser.add_argument("--lora_rank", type=int, default=16,
                        help="LoRA rank r (default: 16)")
    parser.add_argument("--lora_alpha", type=int, default=32,
                        help="LoRA alpha (default: 32)")
    parser.add_argument("--lora_dropout", type=float, default=0.05,
                        help="LoRA dropout (default: 0.05)")
    parser.add_argument("--resume_from_checkpoint", type=str, default=None,
                        help="Resume from checkpoint folder or 'auto'")
    parser.add_argument("--dry_run", action="store_true", default=False,
                        help="Execute pre-flight dry-run forward pass on 10 samples without training/saving")
    parser.add_argument("--config", type=Path, default=None,
                        help="Path to YAML training profile (e.g. configs/kaggle_dual_t4.yaml)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed")
    args = parser.parse_args()

    # Load configuration from YAML if provided
    if args.config and args.config.exists():
        print(f"[*] Loading training profile from: {args.config}")
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
            if isinstance(cfg, dict):
                for k, v in cfg.items():
                    if hasattr(args, k):
                        if k in ["train_path", "val_path", "output_dir"] and v:
                            setattr(args, k, Path(v))
                        else:
                            setattr(args, k, v)

    set_seed(args.seed)

    # 1. Hardware & Environment Preflight
    cuda_available = torch.cuda.is_available()
    gpu_count = torch.cuda.device_count() if cuda_available else 0
    gpu_name = torch.cuda.get_device_name(0) if cuda_available else "N/A"
    gpu_vram_gb = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2) if cuda_available else 0.0
    cuda_cap = torch.cuda.get_device_capability(0) if cuda_available else (0, 0)
    bf16_hardware_support = cuda_available and torch.cuda.is_bf16_supported()

    # 2. Strict Precision Decision for T4 / Turing (Compute Cap < 8.0)
    if args.precision:
        target_precision = args.precision.lower()
    else:
        if cuda_available:
            # If Turing (Cap 7.5) or below, strictly use fp16
            target_precision = "bfloat16" if (cuda_cap[0] >= 8 and bf16_hardware_support) else "fp16"
        else:
            target_precision = "fp32"

    use_fp16 = (target_precision == "fp16") and cuda_available
    use_bf16 = (target_precision == "bfloat16") and cuda_available and bf16_hardware_support
    compute_dtype = torch.float16 if use_fp16 else (torch.bfloat16 if use_bf16 else torch.float32)

    # 3. Batch Size & Grad Accum
    if args.batch_size is None or args.grad_accum is None:
        if cuda_available:
            if gpu_vram_gb < 12.0:
                args.batch_size = args.batch_size or 1
                args.grad_accum = args.grad_accum or 16
            else:
                args.batch_size = args.batch_size or 2
                args.grad_accum = args.grad_accum or 8
        else:
            args.batch_size = args.batch_size or 1
            args.grad_accum = args.grad_accum or 8

    # 4. Memory Estimation
    est_model_gb = 5.4
    est_lora_gb = 0.4
    est_optim_gb = 1.5
    est_activations_gb = round((args.batch_size * args.max_length * 4096 * 36 * 2) / (1024**3), 2)
    est_total_vram_gb = round(est_model_gb + est_lora_gb + est_optim_gb + est_activations_gb, 2)

    print("\n" + "=" * 80)
    print("CYBERQWEN-AI: MASTER QLORA ENVIRONMENT PREFLIGHT & HARDWARE AUDIT")
    print("=" * 80)
    print("SOFTWARE COMPONENT VERSIONS:")
    print(f"  Python Version:          {sys.version.split()[0]}")
    print(f"  PyTorch Version:         {torch.__version__}")
    print(f"  Transformers Version:    {transformers.__version__}")
    print(f"  TRL Version:             {trl.__version__}")
    print(f"  PEFT Version:            {peft.__version__}")
    print(f"  BitsAndBytes Version:    {bnb.__version__}")
    print(f"  CUDA Version:            {torch.version.cuda if torch.version.cuda else 'N/A'}")
    print("-" * 80)
    print("HARDWARE & ACCELERATION:")
    print(f"  CUDA Available:          {cuda_available}")
    print(f"  GPU Count:               {gpu_count}")
    print(f"  GPU Name:                {gpu_name}")
    print(f"  VRAM Available:          {gpu_vram_gb} GB")
    print(f"  CUDA Capability:         {cuda_cap[0]}.{cuda_cap[1]}")
    print(f"  Selected Precision:      {target_precision.upper()} (FP16={use_fp16}, BF16={use_bf16})")
    print(f"  4-Bit Quantization:      NF4 (Double Quant = True, Compute = {str(compute_dtype).split('.')[-1]})")
    print("-" * 80)
    print("TRAINING HYPERPARAMETERS:")
    print(f"  Base Model:              {args.model_id}")
    print(f"  Train Dataset:           {args.train_path}")
    print(f"  Validation Dataset:      {args.val_path}")
    print(f"  Output Directory:        {args.output_dir}")
    print(f"  Batch Size:              {args.batch_size} (per-device) | Grad Accum: {args.grad_accum} | Effective: {args.batch_size * args.grad_accum}")
    print(f"  Epochs:                  {args.epochs} | Learning Rate: {args.lr}")
    print(f"  LoRA Configuration:      r={args.lora_rank}, alpha={args.lora_alpha}, dropout={args.lora_dropout}")
    print(f"  Target Modules:          q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj")
    print(f"  Checkpoint Strategy:     save_strategy='steps', save_steps=10, save_total_limit=3")
    print("-" * 80)
    print("ESTIMATED VRAM REQUIREMENT:")
    print(f"  Model (4-bit NF4):       ~{est_model_gb:.1f} GB")
    print(f"  LoRA Adapter:            ~{est_lora_gb:.1f} GB")
    print(f"  Optimizer States:        ~{est_optim_gb:.1f} GB")
    print(f"  Activation Footprint:    ~{est_activations_gb:.1f} GB")
    print(f"  Total Estimated VRAM:    ~{est_total_vram_gb:.1f} GB (Headroom: {round(gpu_vram_gb - est_total_vram_gb, 1) if cuda_available else 0.0} GB)")
    print("=" * 80)

    if not cuda_available:
        print("\n[WARNING] CPU training detected. Qwen3-8B QLoRA will be extremely slow.")
        print("[WARNING] A CUDA-enabled NVIDIA GPU with >= 8GB VRAM is strongly recommended for production training.\n")

    # 5. Load Datasets
    print("[*] Step 1/5: Loading datasets...")
    data_files = {"train": str(args.train_path)}
    if args.val_path.exists():
        data_files["validation"] = str(args.val_path)
    
    raw_datasets = load_dataset("json", data_files=data_files)
    print(f"[+] Train dataset:      {len(raw_datasets['train'])} samples")
    if "validation" in raw_datasets:
        print(f"[+] Validation dataset: {len(raw_datasets['validation'])} samples")

    # 6. Tokenizer Setup
    print(f"[*] Step 2/5: Initializing tokenizer for {args.model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(args.model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id

    # 7. Model Loading and Quantization
    print(f"[*] Step 3/5: Loading base model {args.model_id} in 4-bit NF4...")
    bnb_config = None
    if cuda_available:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=compute_dtype,
            bnb_4bit_use_double_quant=True
        )

    model_kwargs = {
        "trust_remote_code": True,
        "device_map": "auto" if cuda_available else "cpu",
        "torch_dtype": compute_dtype
    }

    if args.dry_run and not cuda_available:
        print(f"[*] Dry-run mode on CPU: Initializing {args.model_id} architecture for verification...")
        from transformers import AutoConfig
        config = AutoConfig.from_pretrained(args.model_id, trust_remote_code=True)
        config.num_hidden_layers = 2
        model = AutoModelForCausalLM.from_config(config, trust_remote_code=True)
    else:
        if bnb_config:
            model_kwargs["quantization_config"] = bnb_config
        model = AutoModelForCausalLM.from_pretrained(args.model_id, **model_kwargs)

    if cuda_available and bnb_config:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)

    # 8. LoRA Adapter Configuration
    print(f"[*] Step 4/5: Configuring LoRA adapter (r={args.lora_rank}, alpha={args.lora_alpha})...")
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    lora_config = LoraConfig(
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
        target_modules=target_modules
    )

    # 8.1. Handle Dry-Run Mode
    if args.dry_run:
        print("\n" + "=" * 80)
        print("CYBERQWEN-AI: DRY-RUN PRE-FLIGHT TRAINING PASS")
        print("=" * 80)
        print("[*] Dry-run requested: Loading LoRA adapter and running forward pass on 10 samples...")
        peft_model = get_peft_model(model, lora_config)
        peft_model.eval()

        trainable_params, total_params = peft_model.get_nb_trainable_parameters()
        print(f"[+] Trainable Parameters: {trainable_params:,} / {total_params:,} ({100 * trainable_params / total_params:.2f}%)")

        sample_subset = [raw_datasets["train"][i] for i in range(min(10, len(raw_datasets["train"])))]
        sample_texts = [format_chat_data(s, tokenizer) for s in sample_subset]

        print(f"[*] Tokenizing batch of {len(sample_texts)} samples (max_length={args.max_length})...")
        device = next(peft_model.parameters()).device
        inputs = tokenizer(
            sample_texts,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=args.max_length
        ).to(device)

        print("[*] Executing forward pass with causal LM loss calculation...")
        with torch.no_grad():
            outputs = peft_model(**inputs, labels=inputs["input_ids"])
            loss = outputs.loss.item()

        print("\n" + "=" * 80)
        print("DRY-RUN VALIDATION SUCCESSFUL!")
        print("=" * 80)
        print(f"[*] Base Model:            {args.model_id}")
        print(f"[*] Train Dataset:         {len(raw_datasets['train'])} samples")
        print(f"[*] Validation Dataset:    {len(raw_datasets.get('validation', []))} samples")
        print(f"[*] LoRA Status:           Active ({len(peft_model.peft_config)} adapter config)")
        print(f"[*] Computed Forward Loss: {loss:.4f}")
        print(f"[*] Batch Input Shape:     {tuple(inputs['input_ids'].shape)}")
        print(f"[*] Selected Precision:    {target_precision.upper()}")
        print("[*] Pre-flight forward pass verified. Exiting without saving model checkpoints.")
        print("=" * 80 + "\n")
        return

    # 9. SFTTrainer & Monitoring Setup
    args.output_dir.mkdir(parents=True, exist_ok=True)
    checkpoints_dir = args.output_dir / "checkpoints"
    checkpoints_dir.mkdir(parents=True, exist_ok=True)
    
    telemetry_callback = TrainingTelemetryMonitor(total_epochs=args.epochs, grad_accum=args.grad_accum)

    training_args = SFTConfig(
        output_dir=str(checkpoints_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        weight_decay=0.01,
        warmup_steps=5,
        lr_scheduler_type="cosine",
        logging_steps=2,
        eval_strategy="steps" if "validation" in raw_datasets else "no",
        eval_steps=10,
        save_strategy="steps",
        save_steps=10,
        save_total_limit=3,
        max_grad_norm=1.0,
        fp16=use_fp16,
        bf16=use_bf16,
        gradient_checkpointing=cuda_available,
        optim="paged_adamw_8bit" if cuda_available else "adamw_torch",
        report_to="none",
        seed=args.seed,
        dataset_text_field="text",
        max_length=args.max_length
    )

    def prepare_split(split):
        return split.map(
            lambda ex: {"text": format_chat_data(ex, tokenizer)},
            remove_columns=[c for c in split.column_names if c != "text"]
        )

    train_data = prepare_split(raw_datasets["train"])
    eval_data = prepare_split(raw_datasets["validation"]) if "validation" in raw_datasets else None

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_data,
        eval_dataset=eval_data,
        peft_config=lora_config,
        processing_class=tokenizer,
        callbacks=[telemetry_callback]
    )

    # 10. Automatic Checkpoint Recovery
    resume_flag = None
    if args.resume_from_checkpoint:
        if str(args.resume_from_checkpoint).lower() in ["auto", "true", "1", "yes"]:
            latest_ckpt = find_latest_checkpoint(checkpoints_dir) or find_latest_checkpoint(args.output_dir)
            if latest_ckpt:
                resume_flag = str(latest_ckpt)
                print(f"[+] Found existing checkpoint: {resume_flag}. Automatically resuming training...")
        else:
            resume_flag = args.resume_from_checkpoint
    else:
        latest_ckpt = find_latest_checkpoint(checkpoints_dir) or find_latest_checkpoint(args.output_dir)
        if latest_ckpt:
            resume_flag = str(latest_ckpt)
            print(f"[+] Found existing checkpoint: {resume_flag}. Automatically resuming training...")

    # 11. Run Training
    print("\n" + "=" * 80)
    print("LIVE TRAINING TELEMETRY")
    print("=" * 80)

    train_result = trainer.train(resume_from_checkpoint=resume_flag)

    # 12. Save Adapter & Telemetry
    print("\n[*] Step 5/5: Saving final LoRA adapter, tokenizer, and metrics...")
    trainer.model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    metrics_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_model": args.model_id,
        "train_dataset": str(args.train_path),
        "validation_dataset": str(args.val_path),
        "train_runtime_seconds": train_result.metrics.get("train_runtime", 0.0),
        "train_loss": train_result.metrics.get("train_loss", 0.0),
        "total_epochs": args.epochs,
        "global_steps": train_result.global_step,
        "effective_batch_size": args.batch_size * args.grad_accum,
        "learning_rate": args.lr,
        "precision": target_precision,
        "lora_rank": args.lora_rank,
        "lora_alpha": args.lora_alpha,
        "history": telemetry_callback.history
    }

    metrics_file = args.output_dir / "training_metrics.json"
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)

    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    with open(logs_dir / "training_experiment_log.json", "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)

    csv_file = logs_dir / "training_metrics.csv"
    with open(csv_file, "w", encoding="utf-8") as f:
        f.write("step,epoch,loss,val_loss,learning_rate,gpu_vram,gpu_util,elapsed_seconds\n")
        for entry in telemetry_callback.history:
            f.write(f"{entry['step']},{entry['epoch']},{entry['loss']},{entry['val_loss']},{entry['learning_rate']},{entry.get('gpu_vram','N/A')},{entry.get('gpu_util','N/A')},{entry['elapsed_seconds']}\n")

    # Generate Markdown Training Report
    report_md = logs_dir / "TRAINING_COMPLETION_REPORT.md"
    with open(report_md, "w", encoding="utf-8") as f:
        f.write(f"# CyberQwen-AI: QLoRA Fine-Tuning Execution Report\n\n")
        f.write(f"**Completion Timestamp**: {metrics_data['timestamp']}  \n")
        f.write(f"**Base Model**: {args.model_id}  \n")
        f.write(f"**LoRA Adapter Output**: `{args.output_dir}`  \n")
        f.write(f"**Total Training Runtime**: {metrics_data['train_runtime_seconds']:.2f} seconds  \n")
        f.write(f"**Final Train Loss**: {metrics_data['train_loss']:.4f}  \n\n")
        f.write("## Hyperparameters\n")
        f.write(f"- **Epochs**: {args.epochs}\n")
        f.write(f"- **Batch Size**: {args.batch_size} (Effective: {args.batch_size * args.grad_accum})\n")
        f.write(f"- **Learning Rate**: {args.lr}\n")
        f.write(f"- **Precision**: {target_precision.upper()}\n")
        f.write(f"- **LoRA Rank**: {args.lora_rank} (Alpha: {args.lora_alpha}, Dropout: {args.lora_dropout})\n\n")
        f.write("## Loss & Step History\n\n")
        f.write("| Step | Epoch | Train Loss | Val Loss | Learning Rate | VRAM | Elapsed |\n")
        f.write("| :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")
        for entry in telemetry_callback.history:
            f.write(f"| {entry['step']} | {entry['epoch']} | {entry['loss']} | {entry['val_loss']} | {entry['learning_rate']} | {entry.get('gpu_vram','N/A')} | {entry['elapsed_seconds']}s |\n")

    print("=" * 80)
    print("[SUCCESS] FULL QLORA FINE-TUNING COMPLETED!")
    print(f"[*] LoRA Adapter Saved:  {args.output_dir}")
    print(f"[*] Metrics Saved:       {metrics_file}")
    print(f"[*] Report Generated:    {report_md}")
    print(f"[*] Final Train Loss:    {train_result.metrics.get('train_loss', 0.0):.4f}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()
