"""
CyberQwen-AI: Google Gemini Dataset Validator
Provides automated LLM-as-a-Judge validation and scoring for cybersecurity training samples.

Scores:
- Cybersecurity technical accuracy
- Reasoning quality & depth
- Usefulness for QLoRA fine-tuning
- Hallucination & factual verification
- Redundancy & low-quality pattern detection
"""

import os
import sys
import json
import time
import re
import warnings
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from dotenv import load_dotenv

# Suppress deprecation warnings for cleaner CLI output
warnings.filterwarnings("ignore")

import google.generativeai as genai

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Load environment variables
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

DEFAULT_MODEL_NAME = "gemini-3.5-flash-lite"
FALLBACK_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.6-flash",
    "gemini-3.7-flash",
    "gemini-flash-latest"
]

SYSTEM_VALIDATOR_PROMPT = """You are an elite Senior Cybersecurity AI Dataset Quality Auditor and LLM Fine-Tuning Specialist.
Your task is to critically evaluate training examples for fine-tuning CyberQwen-AI (a specialized cybersecurity model for CTF, malware analysis, reverse engineering, forensics, secure coding, and vulnerability analysis).

Evaluate the given example against 5 core criteria:
1. Cybersecurity Accuracy: Are the technical concepts, commands, CVEs, tools, and exploit mechanics 100% accurate?
2. Reasoning Quality: Does the explanation demonstrate clear, step-by-step technical problem solving?
3. Usefulness for Training: Is this realistic, high-signal, and practically beneficial for an AI security assistant?
4. Hallucination Risk: Are there made-up flags, non-existent flags/tools/syntax, or contradictory statements?
5. Completeness & Specificity: Does the response provide concrete commands/code/analysis rather than generic fluff?

Output ONLY a valid JSON object with the following schema:
{
  "score": <float between 0.0 and 10.0>,
  "quality": "<good or bad>",
  "difficulty": "<beginner or intermediate or advanced or expert>",
  "issues": [<list of specific technical flaws, inaccuracies, or missing details>],
  "suggestion": "<actionable recommendation to make this example top-tier>"
}

Difficulty Classification Guidelines:
- beginner: Basic concepts, definitions, simple ciphers (ROT13/Caesar), basic Linux commands, intro web terms.
- intermediate: Multi-step CTF challenges, common web vulnerabilities (SQLi/XSS/SSRF), basic reverse engineering with Ghidra, standard privilege escalation.
- advanced: Binary exploitation (ROP/bypassing NX/ASLR), process injection/evasion, advanced crypto attacks (padding oracles, Bleichenbacher), custom exploit development.
- expert: Deep zero-day root cause analysis, heap feng-shui, kernel-level rootkits, hypervisor/sandbox escapes, advanced cryptographic proofs.

Scoring Guidelines:
- 8.5 to 10.0: High quality, accurate, actionable, complete (Mark "quality": "good")
- 7.0 to 8.4: Good quality with minor omissions (Mark "quality": "good")
- 0.0 to 6.9: Incorrect, generic, hallucinated, incomplete, or low-signal (Mark "quality": "bad")
"""

SYSTEM_IMPROVER_PROMPT = """You are CyberQwen's Senior Cybersecurity Dataset Engineer.
Rewrite and improve the provided training example so it meets the highest standards for QLoRA fine-tuning.
Ensure:
- 100% technical accuracy
- Realistic CTF / security scenario context
- Explicit tools and commands (e.g. gdb, ghidra, volatility, burp, nmap, python, openssl)
- Deep, structured, step-by-step reasoning
- Zero markdown code fences around the JSON itself

Output ONLY a JSON object:
{
  "instruction": "<clear cybersecurity request>",
  "input": "<context, logs, code, or empty string>",
  "output": "<thorough, accurate, and actionable solution>"
}
"""

def get_gemini_client(api_key: Optional[str] = None, model_name: str = DEFAULT_MODEL_NAME):
    """Initializes and returns the configured Gemini GenerativeModel."""
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        raise ValueError("GEMINI_API_KEY not found in environment or .env file.")
    genai.configure(api_key=key)
    return genai.GenerativeModel(model_name=model_name)

def test_gemini_connection(api_key: Optional[str] = None, model_name: str = DEFAULT_MODEL_NAME) -> bool:
    """Tests connection to the Google Gemini API with fallback support."""
    print("Testing Gemini API...")
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        print("[!] API Error: GEMINI_API_KEY is not set.")
        return False

    genai.configure(api_key=key)
    models_to_try = [model_name] + [m for m in FALLBACK_MODELS if m != model_name]

    for m_name in models_to_try:
        try:
            model = genai.GenerativeModel(model_name=m_name)
            response = model.generate_content("Reply with Gemini connection successful")
            reply = response.text.strip()
            print(f"[+] Gemini Response ({m_name}): {reply}")
            print(f"[+] Gemini API connection verified successfully using model '{m_name}'!")
            return True
        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg or "quota" in err_msg.lower():
                print(f"[!] Notice: Model {m_name} rate/quota limit reached. Trying next model...")
                time.sleep(1)
                continue
            elif "404" in err_msg or "not found" in err_msg.lower() or "no longer available" in err_msg.lower():
                print(f"[!] Notice: Model {m_name} not found. Trying next model...")
                continue
            else:
                print(f"[!] API Error on {m_name}: {e}")
                continue

    print("[!] Failed to connect to Gemini API with all available models due to quota limits.")
    return False

def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Extracts JSON object from text even if wrapped in markdown."""
    text = text.strip()
    # Remove markdown code fences if present
    text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fallback: search for first { and last }
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
    return None

def validate_example(
    example: Dict[str, Any],
    api_key: Optional[str] = None,
    model_name: str = DEFAULT_MODEL_NAME,
    max_retries: int = 3,
    retry_delay: float = 2.0
) -> Dict[str, Any]:
    """
    Validates a single cybersecurity dataset example with Google Gemini.
    """
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        return {"score": 0.0, "quality": "bad", "issues": ["Missing GEMINI_API_KEY"], "suggestion": "Set key in .env"}

    genai.configure(api_key=key)
    
    inst = example.get("instruction", "").strip()
    inp = example.get("input", "").strip()
    out = example.get("output", "").strip()

    prompt = f"""{SYSTEM_VALIDATOR_PROMPT}

Candidate Training Example to Evaluate:
----------------------------------------
Instruction: {inst}
Input Context: {inp if inp else "(None)"}
Assistant Output: {out}
----------------------------------------

Provide your JSON evaluation:"""

    models_to_try = [model_name] + [m for m in FALLBACK_MODELS if m != model_name]

    for current_model_name in models_to_try:
        model = genai.GenerativeModel(model_name=current_model_name)
        for attempt in range(1, max_retries + 1):
            try:
                response = model.generate_content(
                    prompt,
                    generation_config={"temperature": 0.2, "top_p": 0.9}
                )
                result = extract_json(response.text)
                if result and "score" in result:
                    score = float(result.get("score", 5.0))
                    score = max(0.0, min(10.0, score))
                    quality = "good" if score >= 7.0 else "bad"
                    if "quality" in result and result["quality"].lower() in ["good", "bad"]:
                        quality = result["quality"].lower()
                    
                    issues = result.get("issues", [])
                    if isinstance(issues, str):
                        issues = [issues]
                    elif not isinstance(issues, list):
                        issues = []
                        
                    suggestion = str(result.get("suggestion", "")).strip()

                    # Extract difficulty
                    diff = str(result.get("difficulty", "intermediate")).strip().lower()
                    if diff not in ["beginner", "intermediate", "advanced", "expert"]:
                        # Infer difficulty from score or complexity if ambiguous
                        if score >= 9.0:
                            diff = "advanced"
                        elif score >= 7.0:
                            diff = "intermediate"
                        else:
                            diff = "beginner"

                    return {
                        "score": round(score, 1),
                        "quality": quality,
                        "difficulty": diff,
                        "issues": issues,
                        "suggestion": suggestion
                    }
            except Exception as e:
                err_str = str(e).lower()
                if "429" in err_str or "quota" in err_str:
                    break  # Try next model immediately
                if attempt < max_retries:
                    time.sleep(retry_delay * attempt)
    
    return {
        "score": 5.0,
        "quality": "bad",
        "issues": ["Gemini validation quota reached across models or parsing issue."],
        "suggestion": "Retry with higher quota tier or wait for minute window reset."
    }

def improve_example(
    example: Dict[str, Any],
    feedback: Optional[Dict[str, Any]] = None,
    api_key: Optional[str] = None,
    model_name: str = DEFAULT_MODEL_NAME,
    max_retries: int = 3
) -> Dict[str, Any]:
    """
    Uses Google Gemini to rewrite and improve a cybersecurity example.
    """
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        return example

    genai.configure(api_key=key)
    
    inst = example.get("instruction", "").strip()
    inp = example.get("input", "").strip()
    out = example.get("output", "").strip()
    
    issues_text = ""
    if feedback and feedback.get("issues"):
        issues_text = "\nIssues to fix:\n- " + "\n- ".join(feedback["issues"])
    if feedback and feedback.get("suggestion"):
        issues_text += f"\nSuggestion: {feedback['suggestion']}"

    prompt = f"""{SYSTEM_IMPROVER_PROMPT}

Original Example:
-----------------
Instruction: {inst}
Input: {inp if inp else "(None)"}
Output: {out}
-----------------
{issues_text}

Provide improved JSON:"""

    models_to_try = [model_name] + [m for m in FALLBACK_MODELS if m != model_name]

    for current_model_name in models_to_try:
        model = genai.GenerativeModel(model_name=current_model_name)
        for attempt in range(1, max_retries + 1):
            try:
                response = model.generate_content(
                    prompt,
                    generation_config={"temperature": 0.4, "top_p": 0.9}
                )
                improved = extract_json(response.text)
                if improved and "instruction" in improved and "output" in improved:
                    return {
                        "instruction": improved.get("instruction", inst).strip(),
                        "input": improved.get("input", inp).strip(),
                        "output": improved.get("output", out).strip()
                    }
            except Exception as e:
                if "429" in str(e) or "quota" in str(e).lower():
                    break  # Try next model
                time.sleep(1.5 * attempt)

    return example

if __name__ == "__main__":
    test_gemini_connection()
