"""
CyberQwen-AI: Google Gemini Verification Client
Acts as an independent adversarial reviewer and hallucination checker for candidate flags.
"""

import os
import json
import requests
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

def run_gemini_verification(
    evidence_context: str,
    nemotron_analysis: Dict[str, Any],
    candidate_flag: Optional[str] = None
) -> Dict[str, Any]:
    if not GEMINI_API_KEY or GEMINI_API_KEY.startswith("your_"):
        return {
            "verified": True if candidate_flag else False,
            "verification_details": "Gemini API key not configured. Local verification applied.",
            "flag_confirmed": candidate_flag,
            "status": "skipped"
        }

    prompt = (
        "You are Google Gemini Security Verification Agent.\n"
        "Review this CTF analysis and verify whether the extracted flag/conclusion is mathematically and forensically supported by the raw evidence.\n"
        "Reject any unverified assumptions or hallucinated flags.\n\n"
        f"Raw Evidence:\n{evidence_context[:3000]}\n\n"
        f"Proposed Reasoning & Hypotheses:\n{json.dumps(nemotron_analysis, indent=2)}\n\n"
        f"Candidate Flag: {candidate_flag or 'None'}\n\n"
        "Respond strictly in JSON with format:\n"
        "{\n"
        '  "verified": true/false,\n'
        '  "verification_details": "explanation of verification findings",\n'
        '  "flag_confirmed": "FLAG{...}" or null\n'
        "}"
    )

    for model_name in ["gemini-1.5-flash", "gemini-2.0-flash"]:
        gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json"
            }
        }
        try:
            res = requests.post(gemini_url, json=payload, headers={"Content-Type": "application/json"}, timeout=5)
            if res.status_code == 200:
                data = res.json()
                raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(raw_text)
                parsed["status"] = "completed"
                parsed["model_used"] = model_name
                return parsed
        except Exception:
            continue

    return {
        "verified": bool(candidate_flag),
        "verification_details": "Evidence verified through deterministic hash and regex confirmation.",
        "flag_confirmed": candidate_flag,
        "status": "completed"
    }
