"""
CyberQwen-AI: Multi-Model Reasoning Orchestrator
Coordinates collaborative inference between CyberQwen (Primary), NVIDIA Nemotron (Reasoning),
and Google Gemini (Verification & Hallucination Guard).
"""

import time
from typing import Dict, Any, Optional
from backend.nemotron_client import run_nemotron_reasoning
from backend.gemini_client import run_gemini_verification

class MultiModelReasoningOrchestrator:
    def __init__(self, cyber_service):
        self.cyber_service = cyber_service

    def execute_reasoning_pipeline(
        self,
        filename: str,
        extracted_data: Dict[str, Any],
        mode: str = "hybrid",
        action: str = "ctf_assistant"
    ) -> Dict[str, Any]:
        """
        Executes multi-model consensus workflow based on selected mode.
        Modes: 'local', 'nemotron', 'gemini', 'hybrid'
        """
        start_time = time.time()
        evidence_context = extracted_data["context"]
        discovered_flags = extracted_data.get("discovered_flags", [])
        initial_flag = discovered_flags[0] if discovered_flags else None

        nemotron_res = {"status": "skipped", "analysis": "N/A", "confidence": "N/A", "possible_flag": None}
        gemini_res = {"status": "skipped", "verified": False, "verification_details": "N/A", "flag_confirmed": None}

        # Step 1 & 2: Nemotron Deep Reasoning
        if mode in ["nemotron", "hybrid"]:
            print(f"[*] Dispatching evidence from '{filename}' to NVIDIA Nemotron...")
            nemotron_res = run_nemotron_reasoning(evidence_context, filename)
            if nemotron_res.get("possible_flag") and not initial_flag:
                initial_flag = nemotron_res["possible_flag"]

        # Step 3: Gemini Verification
        if mode in ["gemini", "hybrid"]:
            print(f"[*] Dispatching hypotheses to Google Gemini Verification Agent...")
            candidate = initial_flag or nemotron_res.get("possible_flag")
            gemini_res = run_gemini_verification(evidence_context, nemotron_res, candidate)
            if gemini_res.get("flag_confirmed"):
                initial_flag = gemini_res["flag_confirmed"]

        # Step 4: CyberQwen Final Consensus Synthesis
        print(f"[*] Generating final CyberQwen synthesis (Mode: {mode.upper()})...")
        consensus_status = "verified" if (gemini_res.get("verified") or initial_flag) else "unverified"

        # Backend Telemetry Log (As Required)
        print("\n" + "=" * 60)
        print("MODEL PIPELINE\n")
        print(f"Evidence:\n{filename}\n")
        print(f"Nemotron:\n{nemotron_res.get('status', 'skipped')}\n")
        print(f"Gemini:\n{gemini_res.get('status', 'skipped')}\n")
        print(f"Consensus:\n{consensus_status}\n")
        print("=" * 60 + "\n")

        # Synthesize Final Structured Report
        final_flag_section = ""
        if initial_flag and gemini_res.get("verified", True):
            final_flag_section = f"FLAG FOUND:\n{initial_flag}"
        else:
            final_flag_section = (
                "FLAG NOT VERIFIED\n"
                "The current evidence is insufficient to verify the exact flag without additional artifacts."
            )

        nemotron_summary = nemotron_res.get("analysis", "Direct local CyberQwen processing.")
        gemini_summary = gemini_res.get("verification_details", "Local heuristic verification.")

        report = (
            f"### CYBERQWEN REPORT\n\n"
            f"**Target Archive / File**: `{filename}`\n"
            f"**Reasoning Pipeline**: `{mode.upper()}` (CyberQwen + Nemotron + Gemini)\n\n"
            f"#### Challenge Type:\n"
            f"Forensics & Cryptographic Analysis\n\n"
            f"#### Evidence:\n"
            f"{extracted_data['evidence_summary']}\n\n"
            f"#### Nemotron Analysis:\n"
            f"{nemotron_summary}\n\n"
            f"#### Gemini Verification:\n"
            f"{gemini_summary}\n\n"
            f"#### Final Decision:\n"
            f"{final_flag_section}"
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 1)

        return {
            "filename": filename,
            "mode": mode,
            "response": report,
            "nemotron_status": nemotron_res.get("status"),
            "gemini_status": gemini_res.get("status"),
            "consensus": consensus_status,
            "final_flag": initial_flag if gemini_res.get("verified", True) else None,
            "latency_ms": elapsed_ms,
            "tokens": len(report.split())
        }
