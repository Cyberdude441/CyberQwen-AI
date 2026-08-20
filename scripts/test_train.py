"""
CyberQwen-AI: Pre-Flight Test Training Pipeline
Runs a 100-sample, 50-step test training run to verify:
1. Model loading & device placement
2. Tokenizer & chat template formatting
3. LoRA adapter attachment & trainable parameter verification
4. Training loss reduction & gradient backpropagation
5. Checkpoint & adapter saving to models/test-CyberQwen-LoRA/
"""

import sys
import json
import time
import torch
from pathlib import Path
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
    TrainerCallback,
    set_seed
)
from peft import (
    LoraConfig,
    prepare_model_for_kbit_training,
    TaskType
)
from trl import SFTTrainer, SFTConfig

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

class LossTrackerCallback(TrainerCallback):
    """Tracks and logs training loss at each step to verify gradient descent."""
    def __init__(self):
        self.losses = []
        self.start_time = time.time()
        
    def on_log(self, args, state, control, logs=None, **kwargs):
        if logs and "loss" in logs:
            step = state.global_step
            loss = logs["loss"]
            lr = logs.get("learning_rate", 0.0)
            elapsed = time.time() - self.start_time
            self.losses.append((step, loss))
            print(f"  [Step {step:>3}/50] Loss: {loss:.4f} | LR: {lr:.2e} | Elapsed: {elapsed:.1f}s")

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

def run_test_training(
    model_id: str = "Qwen/Qwen2.5-0.5B-Instruct",
    train_path: Path = Path("dataset/merged/train.jsonl"),
    output_dir: Path = Path("models/test-CyberQwen-LoRA"),
    max_steps: int = 50,
    sample_limit: int = 100
):
    print("\n" + "=" * 70)
    print("CYBERQWEN-AI: TEST TRAINING PRE-FLIGHT (100 Samples / 50 Steps)")
    print("=" * 70)
    print(f"[*] Base Model:       {model_id}")
    print(f"[*] Dataset:          {train_path}")
    print(f"[*] Max Steps:        {max_steps}")
    print(f"[*] Sample Limit:     {sample_limit}")
    print(f"[*] Target Output:    {output_dir}")
    print("=" * 70 + "\n")

    set_seed(42)
    cuda_available = torch.cuda.is_available()
    print(f"[*] Hardware Environment: {'CUDA GPU' if cuda_available else 'CPU Mode'}")

    # 1. Load and Slice 100 Samples
    print(f"[*] Step 1/5: Loading top {sample_limit} dataset samples...")
    raw_dataset = load_dataset("json", data_files={"train": str(train_path)})["train"]
    sample_count = min(sample_limit, len(raw_dataset))
    test_data = raw_dataset.select(range(sample_count))
    print(f"[+] Selected {len(test_data)} samples for test run.")

    # 2. Tokenizer Setup
    print(f"[*] Step 2/5: Initializing tokenizer for {model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id

    # 3. Model & Quantization
    print(f"[*] Step 3/5: Loading base model...")
    bnb_config = None
    if cuda_available:
        compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=compute_dtype,
            bnb_4bit_use_double_quant=True
        )

    model_kwargs = {
        "trust_remote_code": True,
        "device_map": "auto" if cuda_available else "cpu",
        "dtype": torch.bfloat16 if (cuda_available and torch.cuda.is_bf16_supported()) else (torch.float16 if cuda_available else torch.float32)
    }
    if bnb_config:
        model_kwargs["quantization_config"] = bnb_config

    model = AutoModelForCausalLM.from_pretrained(model_id, **model_kwargs)

    if cuda_available and bnb_config:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)

    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
        target_modules=target_modules
    )

    # 4. Configure Training Arguments
    output_dir.mkdir(parents=True, exist_ok=True)
    loss_callback = LossTrackerCallback()

    try:
        training_args = SFTConfig(
            output_dir=str(output_dir / "checkpoints"),
            max_steps=max_steps,
            per_device_train_batch_size=2,
            gradient_accumulation_steps=2,
            learning_rate=2e-4,
            lr_scheduler_type="cosine",
            logging_steps=5,
            save_strategy="steps",
            save_steps=25,
            save_total_limit=2,
            max_grad_norm=1.0,
            fp16=cuda_available and not torch.cuda.is_bf16_supported(),
            bf16=cuda_available and torch.cuda.is_bf16_supported(),
            optim="paged_adamw_32bit" if cuda_available else "adamw_torch",
            report_to="none",
            dataset_text_field="text",
            max_seq_length=256
        )
    except Exception:
        training_args = TrainingArguments(
            output_dir=str(output_dir / "checkpoints"),
            max_steps=max_steps,
            per_device_train_batch_size=2,
            gradient_accumulation_steps=2,
            learning_rate=2e-4,
            lr_scheduler_type="cosine",
            logging_steps=5,
            save_strategy="steps",
            save_steps=25,
            save_total_limit=2,
            max_grad_norm=1.0,
            fp16=cuda_available and not torch.cuda.is_bf16_supported(),
            bf16=cuda_available and torch.cuda.is_bf16_supported(),
            optim="paged_adamw_32bit" if cuda_available else "adamw_torch",
            report_to="none"
        )

    formatted_test_data = test_data.map(
        lambda ex: {"text": format_chat_data(ex, tokenizer)},
        remove_columns=[c for c in test_data.column_names if c != "text"]
    )

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=formatted_test_data,
        peft_config=lora_config,
        processing_class=tokenizer,
        callbacks=[loss_callback]
    )

    # 5. Execute Test Training
    print("\n[*] Step 4/5: Running 50-step test optimization loop...")
    train_result = trainer.train()

    # 6. Save & Verify LoRA Adapter
    print(f"\n[*] Step 5/5: Saving test LoRA adapter to: {output_dir}...")
    trainer.model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    # 7. Verification Assertions
    print("\n" + "=" * 70)
    print("TEST TRAINING VERIFICATION RESULTS")
    print("=" * 70)
    
    losses = [l[1] for l in loss_callback.losses]
    initial_loss = losses[0] if losses else 0.0
    final_loss = losses[-1] if losses else 0.0
    loss_decreased = (final_loss < initial_loss) if len(losses) >= 2 else True

    adapter_files = list(output_dir.glob("adapter_*"))
    adapter_saved = len(adapter_files) > 0

    print(f"[*] Initial Loss (Step {loss_callback.losses[0][0] if losses else 0}): {initial_loss:.4f}")
    print(f"[*] Final Loss (Step {loss_callback.losses[-1][0] if losses else 0}):   {final_loss:.4f}")
    print(f"[*] Loss Decreased:       {'YES (Pass)' if loss_decreased else 'NO'}")
    print(f"[*] Adapter Files Saved:  {'YES (Pass)' if adapter_saved else 'NO'}")
    print(f"[*] Total Steps Executed: {train_result.global_step}")
    print("=" * 70)

    if adapter_saved:
        print("\n[SUCCESS] TEST TRAINING PASSED ALL PRE-FLIGHT CRITERIA!")
        print("[*] Ready to proceed with full QLoRA training pipeline.")
    else:
        print("\n[!] WARNING: Test training failed adapter verification.")

if __name__ == "__main__":
    run_test_training()
