"""
CyberQwen-AI: Ollama Model Deployment and Modelfile Generator
Generates the CyberQwen Modelfile and registers the model in Ollama.
"""

import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DEFAULT_SYSTEM_PROMPT = """You are CyberQwen AI,
a cybersecurity assistant specialized in:
CTF solving,
digital forensics,
OSINT,
malware analysis,
reverse engineering,
secure coding,
web security."""

def generate_modelfile(
    base_model: str,
    output_path: Path,
    system_prompt: str,
    temperature: float = 0.7,
    top_p: float = 0.9
) -> str:
    """Creates an Ollama Modelfile with customized system prompt and parameters."""
    content = f"""FROM {base_model}

# Custom System Prompt for Cybersecurity Operations
SYSTEM \"\"\"{system_prompt}\"\"\"

# Hyperparameters
PARAMETER temperature {temperature}
PARAMETER top_p {top_p}
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
PARAMETER stop "<|im_start|>"
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    print(f"[+] Modelfile generated at: {output_path}")
    return content

def register_ollama_model(model_name: str, modelfile_path: Path) -> bool:
    """Builds and registers the model in the local Ollama instance."""
    print(f"\n[*] Creating Ollama model '{model_name}' from {modelfile_path}...")
    
    # Try using Ollama Python client first
    try:
        import ollama
        print(f"[*] Calling ollama.create(model='{model_name}', from_='{modelfile_path}')...")
        response = ollama.create(model=model_name, from_=str(modelfile_path))
        print(f"[+] Successfully registered '{model_name}' in Ollama!")
        return True
    except Exception as e:
        print(f"[!] Ollama Python SDK create failed ({e}). Falling back to Ollama CLI...")

    # Fallback to Ollama CLI executable
    ollama_bin = shutil.which("ollama") or "ollama"
    try:
        cmd = [ollama_bin, "create", model_name, "-f", str(modelfile_path)]
        print(f"[*] Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="utf-8")
        print(result.stdout)
        print(f"[+] Successfully created Ollama model: {model_name}")
        return True
    except FileNotFoundError:
        print(f"[!] 'ollama' executable not found in PATH. Please install Ollama from https://ollama.ai")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Ollama CLI failed with exit code {e.returncode}: {e.stderr}")
        return False

def verify_ollama_model(model_name: str):
    """Sends a quick cybersecurity test query to the new model."""
    print(f"\n[*] Verifying '{model_name}' with test query...")
    try:
        import ollama
        test_prompt = "What is your primary specialty and what domains can you assist with?"
        response = ollama.chat(
            model=model_name,
            messages=[{"role": "user", "content": test_prompt}]
        )
        print("\n" + "=" * 70)
        print(f"[RESPONSE FROM {model_name.upper()}]:")
        print(response["message"]["content"])
        print("=" * 70)
        print("\n[SUCCESS] Model verified and active in Ollama!")
    except Exception as e:
        print(f"[!] Verification test failed: {e}")
        print("[!] Ensure the Ollama background service is running ('ollama serve').")

def main():
    parser = argparse.ArgumentParser(description="CyberQwen-AI: Ollama Model Builder")
    parser.add_argument("--base_model", type=str, default="qwen3:8b",
                        help="Base Ollama model or GGUF path (default: qwen3:8b)")
    parser.add_argument("--model_name", type=str, default="cyberqwen",
                        help="Target Ollama model name (default: cyberqwen)")
    parser.add_argument("--modelfile", type=Path, default=Path("Modelfile"),
                        help="Modelfile destination path (default: Modelfile)")
    parser.add_argument("--temperature", type=float, default=0.7,
                        help="Sampling temperature (default: 0.7)")
    parser.add_argument("--top_p", type=float, default=0.9,
                        help="Top-p sampling (default: 0.9)")
    parser.add_argument("--create", action="store_true", default=True,
                        help="Automatically run 'ollama create' (default: True)")
    parser.add_argument("--test", action="store_true", default=False,
                        help="Send test prompt to model after creation")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("CYBERQWEN-AI: OLLAMA MODEL CREATION")
    print("=" * 70)
    print(f"[*] Target Model Name: {args.model_name}")
    print(f"[*] Base Model / GGUF: {args.base_model}")
    print(f"[*] Modelfile Path:    {args.modelfile}")
    print("=" * 70 + "\n")

    generate_modelfile(
        base_model=args.base_model,
        output_path=args.modelfile,
        system_prompt=DEFAULT_SYSTEM_PROMPT,
        temperature=args.temperature,
        top_p=args.top_p
    )

    if args.create:
        success = register_ollama_model(args.model_name, args.modelfile)
        if success and args.test:
            verify_ollama_model(args.model_name)

    print("\n" + "=" * 70)
    print("HOW TO RUN YOUR MODEL:")
    print(f"  1. In terminal:    ollama run {args.model_name}")
    print(f"  2. In Aider:       aider --model ollama/{args.model_name}")
    print(f"  3. Benchmark test: python scripts/evaluate_model.py --ollama_model {args.model_name}")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
