"""
CyberQwen-AI: FastAPI Live REST API Server
Provides endpoints for conversational chat, multi-format file analysis, and health telemetry.
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

app = FastAPI(
    title="CyberQwen-AI Backend API",
    description="Live inference and cybersecurity file analysis API for CyberQwen-8B",
    version="1.0.0"
)

# Enable CORS for Vite frontend (http://localhost:5173) and any local client
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize single in-memory model service instance
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
    action: Optional[str] = Form(default="vulnerability_analysis"),
    custom_prompt: Optional[str] = Form(default=None)
):
    try:
        content_bytes = await file.read()
        filename = file.filename or "uploaded_file.txt"
        extracted_text = cyber_service.extract_text_from_file(filename, content_bytes)
        
        # Build task-specific cybersecurity prompt
        action_map = {
            "vulnerability_analysis": (
                f"Perform a comprehensive Vulnerability and Security Assessment of the file `{filename}` below.\n"
                f"Structure your response with:\n"
                f"1. **Vulnerability Summary**\n"
                f"2. **Risk Level** (Critical / High / Medium / Low / Safe)\n"
                f"3. **Technical Explanation & Exploitation Vectors**\n"
                f"4. **Actionable Remediation & Secure Code Fix**\n\n"
                f"File Content:\n```\n{extracted_text[:4000]}\n```"
            ),
            "code_review": (
                f"Conduct an in-depth Secure Code Review of `{filename}` against OWASP Top 10 and CWE standards.\n"
                f"Highlight dangerous functions, memory leaks, injection points, and provide refactored secure code.\n\n"
                f"Code Content:\n```\n{extracted_text[:4000]}\n```"
            ),
            "log_analysis": (
                f"Analyze the following security/system log file `{filename}` for indicators of compromise (IoCs), "
                f"brute force attempts, abnormal traffic spikes, or lateral movement patterns.\n\n"
                f"Log Content:\n```\n{extracted_text[:4000]}\n```"
            ),
            "cve_explainer": (
                f"Explain the vulnerabilities, affected components, root cause, and vendor patch advisories for `{filename}`:\n\n"
                f"Content:\n```\n{extracted_text[:4000]}\n```"
            ),
            "ctf_assistant": (
                f"Act as a competitive CTF solving assistant for the challenge/source code file `{filename}`.\n"
                f"Identify weaknesses, cryptographic flaws, or binary/web exploitation paths and write a solver script.\n\n"
                f"Content:\n```\n{extracted_text[:4000]}\n```"
            )
        }

        prompt = custom_prompt if custom_prompt else action_map.get(action, action_map["vulnerability_analysis"])

        result = cyber_service.generate_response(message=prompt, max_new_tokens=1500, temperature=0.5)
        return {
            "filename": filename,
            "action": action,
            "extracted_length": len(extracted_text),
            "response": result["response"],
            "tokens": result["tokens"],
            "latency_ms": result["latency_ms"]
        }
    except Exception as e:
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
