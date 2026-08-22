"""
CyberQwen-AI: FastAPI Live REST API Server
Provides endpoints for conversational chat, multi-model collaborative analysis, and health telemetry.
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
from backend.reasoning_orchestrator import MultiModelReasoningOrchestrator

app = FastAPI(
    title="CyberQwen-AI Multi-Model Reasoning Backend",
    description="Collaborative intelligence platform powering CyberQwen-8B, NVIDIA Nemotron, and Google Gemini",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cyber_service = CyberQwenService()
orchestrator = MultiModelReasoningOrchestrator(cyber_service)

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[ChatMessage]] = None
    system_prompt: Optional[str] = None
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1024
    mode: Optional[str] = "hybrid"

class AnalysisRequest(BaseModel):
    action: str
    content: str
    context: Optional[str] = ""
    mode: Optional[str] = "hybrid"

@app.get("/")
def root():
    return {
        "service": "CyberQwen-AI Multi-Model Backend API",
        "status": "online",
        "models": {
            "primary": "CyberQwen-8B",
            "reasoning": "NVIDIA Nemotron-70B",
            "verification": "Google Gemini 1.5/2.0 Flash"
        },
        "endpoints": ["/health", "/chat", "/upload", "/analyze"]
    }

@app.get("/health")
def health():
    return {
        "status": "running",
        "model": "CyberQwen",
        "weights_path": str(cyber_service.model_path),
        "device": cyber_service.device,
        "is_loaded": cyber_service.is_loaded,
        "multi_model_ready": True
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
    mode: Optional[str] = Form(default="hybrid"),
    custom_prompt: Optional[str] = Form(default=None)
):
    try:
        content_bytes = await file.read()
        filename = file.filename or "uploaded_file.bin"
        
        # 1. Process ZIP archive or single file into structured forensic context
        extracted = process_file_or_zip(filename, content_bytes)
        
        # 2. Terminal Backend Logging
        print("\n" + "=" * 60)
        print(f"UPLOAD:\n{filename}")
        print("EXTRACTED:")
        for fn in extracted["file_names"]:
            print(f"- {fn}")
        print(f"CONTEXT SIZE:\n{extracted['estimated_tokens']} tokens")
        print("MODEL INPUT:\nverified")
        print("=" * 60 + "\n")

        # 3. Multi-Model Reasoning Pipeline Execution
        orchestrator_result = orchestrator.execute_reasoning_pipeline(
            filename=filename,
            extracted_data=extracted,
            mode=mode or "hybrid",
            action=action
        )

        return {
            "filename": filename,
            "action": action,
            "mode": mode,
            "is_archive": extracted["is_archive"],
            "file_names": extracted.get("file_names", []),
            "file_count": extracted.get("file_count", len(extracted.get("file_names", []))),
            "files_metadata": extracted.get("files_metadata", []),
            "discovered_flags": extracted.get("discovered_flags", []),
            "estimated_tokens": extracted.get("estimated_tokens", 100),
            "response": orchestrator_result["response"],
            "nemotron_status": orchestrator_result["nemotron_status"],
            "gemini_status": orchestrator_result["gemini_status"],
            "consensus": orchestrator_result["consensus"],
            "tokens": orchestrator_result["tokens"],
            "latency_ms": orchestrator_result["latency_ms"]
        }
    except Exception as e:
        print(f"[!] Upload processing error: {e}")
        raise HTTPException(status_code=500, detail=f"File processing error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
