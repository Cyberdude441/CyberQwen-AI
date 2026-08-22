"""
CyberQwen-AI: FastAPI Live REST API Server
Provides endpoints for conversational chat, multi-format file/archive analysis, and health telemetry.
"""

import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from backend.model_service import CyberQwenService
from backend.archive_processor import process_file_or_zip

app = FastAPI(
    title="CyberQwen-AI Backend API",
    description="Live inference and cybersecurity file/archive analysis API for CyberQwen-8B",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cyber_service = CyberQwenService()

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[ChatMessage]] = None
    system_prompt: Optional[str] = None
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1024

class AnalysisRequest(BaseModel):
    action: str
    content: str
    context: Optional[str] = ""

@app.get("/")
def root():
    return {
        "service": "CyberQwen-AI Backend API",
        "status": "online",
        "endpoints": ["/health", "/chat", "/upload", "/analyze"]
    }

@app.get("/health")
def health():
    return {
        "status": "running",
        "model": "CyberQwen",
        "weights_path": str(cyber_service.model_path),
        "device": cyber_service.device,
        "is_loaded": cyber_service.is_loaded
    }

@app.post("/chat")
def chat(payload: ChatRequest):
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    history_dicts = None
    if payload.history:
        history_dicts = [{"role": m.role, "content": m.content} for m in payload.history]

    result = cyber_service.generate_response(
        message=payload.message,
        history=history_dicts,
        system_prompt=payload.system_prompt,
        max_new_tokens=payload.max_tokens or 1024,
        temperature=payload.temperature or 0.7
    )
    return result

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    action: Optional[str] = Form(default="ctf_assistant"),
    custom_prompt: Optional[str] = Form(default=None)
):
    try:
        content_bytes = await file.read()
        filename = file.filename or "uploaded_file.bin"
        
        extracted = process_file_or_zip(filename, content_bytes)
        file_list_str = "\n".join([f"- {name}" for name in extracted["file_names"]])
        
        # Terminal Backend Logging
        print("\n" + "=" * 60)
        print(f"UPLOAD:\n{filename}")
        print("EXTRACTED:")
        for fn in extracted["file_names"]:
            print(f"- {fn}")
        print(f"CONTEXT SIZE:\n{extracted['estimated_tokens']} tokens")
        print("MODEL INPUT:\nverified")
        print("=" * 60 + "\n")

        # CTF Solver Prompt with Chain-of-Evidence Reasoning
        if action == "ctf_assistant":
            system_prompt = (
                "You are CyberQwen CTF Solver.\n"
                "Your objective is to recover the exact flag from authorized challenge evidence.\n"
                "Analyze all provided files.\n"
                "Do not stop at recommendations.\n\n"
                "Perform:\n"
                "1. Evidence extraction\n"
                "2. Pattern identification\n"
                "3. Decoding/decryption reasoning\n"
                "4. Verification\n"
                "5. Flag extraction\n\n"
                "Only output a flag when confirmed.\n\n"
                "Final response format:\n\n"
                "Challenge Type:\n"
                "Evidence:\n"
                "Analysis:\n"
                "Solution:\n"
                "FLAG FOUND:\n"
                "FLAG{...}\n\n"
                "If flag cannot be confirmed, output:\n"
                "FLAG NOT RECOVERED\n<explanation>"
            )
            
            user_prompt = (
                f"Analyze this authorized CTF challenge and recover the exact flag based on the evidence below:\n\n"
                f"{extracted['context']}"
            )
        elif action == "vulnerability_analysis":
            system_prompt = "You are CyberQwen Security Auditor. Perform rigorous vulnerability discovery and triage."
            user_prompt = (
                f"Vulnerability Assessment on target files:\n\n"
                f"{extracted['context']}\n\n"
                f"Provide:\n"
                f"1. **Vulnerability Summary**\n"
                f"2. **Risk Level** (Critical / High / Medium / Low / Safe)\n"
                f"3. **Technical Explanation & Root Cause**\n"
                f"4. **Actionable Remediation & Patched Code**"
            )
        elif action == "code_review":
            system_prompt = "You are CyberQwen Secure Code Auditor. Review code against OWASP Top 10 and CWE standards."
            user_prompt = (
                f"Secure Code Review on target files:\n\n"
                f"{extracted['context']}\n\n"
                f"Highlight insecure patterns, memory flaws, injection risks, and provide secure refactored code."
            )
        elif action == "log_analysis":
            system_prompt = "You are CyberQwen Incident Responder. Analyze security logs for intrusion signals and IoCs."
            user_prompt = (
                f"Security Log Analysis on target stream:\n\n"
                f"{extracted['context']}\n\n"
                f"Summarize threat timeline, suspicious IP/user entities, and defense response."
            )
        else:
            system_prompt = "You are CyberQwen AI, an elite cybersecurity operational assistant."
            user_prompt = f"Analyze the following evidence:\n\n{extracted['context']}"

        if custom_prompt:
            user_prompt += f"\n\nOperator Directive: {custom_prompt}"

        result = cyber_service.generate_response(
            message=user_prompt,
            system_prompt=system_prompt,
            max_new_tokens=1500,
            temperature=0.2
        )
        
        return {
            "filename": filename,
            "action": action,
            "is_archive": extracted["is_archive"],
            "file_names": extracted["file_names"],
            "file_count": extracted["file_count"],
            "files_metadata": extracted["files_metadata"],
            "discovered_flags": extracted["discovered_flags"],
            "estimated_tokens": extracted["estimated_tokens"],
            "response": result["response"],
            "tokens": result["tokens"],
            "latency_ms": result["latency_ms"]
        }
    except Exception as e:
        print(f"[!] Upload processing error: {e}")
        raise HTTPException(status_code=500, detail=f"File processing error: {str(e)}")

@app.post("/analyze")
def analyze_snippet(payload: AnalysisRequest):
    action_prompts = {
        "vulnerability_analysis": f"Perform a vulnerability analysis on the following technical artifact:\n```\n{payload.content[:4000]}\n```",
        "code_review": f"Review this source code for security vulnerabilities and suggest patches:\n```\n{payload.content[:4000]}\n```",
        "log_analysis": f"Inspect these security logs for intrusion signals or IoCs:\n```\n{payload.content[:4000]}\n```",
        "cve_explainer": f"Analyze and explain this CVE / vulnerability advisory:\n```\n{payload.content[:4000]}\n```",
        "ctf_assistant": f"Provide CTF strategy and exploitation solution for this problem:\n```\n{payload.content[:4000]}\n```"
    }
    prompt = action_prompts.get(payload.action, f"Analyze this cybersecurity artifact:\n{payload.content}")
    if payload.context:
        prompt += f"\n\nAdditional Context: {payload.context}"
        
    result = cyber_service.generate_response(message=prompt, max_new_tokens=1500)
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
