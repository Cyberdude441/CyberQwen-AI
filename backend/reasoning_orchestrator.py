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
        Executes multi-model consensus workflow using the Deep Forensic Evidence Manifest.
        """
        start_time = time.time()
        evidence_manifest = extracted_data["manifest"]
        discovered_flags = extracted_data.get("discovered_flags", [])
        initial_flag = discovered_flags[0] if discovered_flags else None

        nemotron_res = {"status": "skipped", "analysis": "N/A", "confidence": "N/A", "possible_flag": None}
        gemini_res = {"status": "skipped", "verified": False, "verification_details": "N/A", "flag_confirmed": None}

        # Step 1 & 2: Nemotron Deep Reasoning on Forensic Manifest
        if mode in ["nemotron", "hybrid"]:
            print(f"[*] Dispatching deep forensic manifest from '{filename}' to NVIDIA Nemotron...")
            nemotron_res = run_nemotron_reasoning(evidence_manifest, filename)
            if nemotron_res.get("possible_flag") and not initial_flag:
                initial_flag = nemotron_res["possible_flag"]

        # Step 3: Gemini Verification & Adversarial Hallucination Guard
        if mode in ["gemini", "hybrid"]:
            print(f"[*] Dispatching evidence + hypotheses to Google Gemini Verification Agent...")
            candidate = initial_flag or nemotron_res.get("possible_flag")
            gemini_res = run_gemini_verification(evidence_manifest, nemotron_res, candidate)
            if gemini_res.get("flag_confirmed"):
                initial_flag = gemini_res["flag_confirmed"]

        # Step 4: CyberQwen Final Consensus Synthesis
        print(f"[*] Synthesizing final CyberQwen Hybrid Consensus (Mode: {mode.upper()})...")
        consensus_status = "verified" if (gemini_res.get("verified") or initial_flag) else "unverified"
        confidence_pct = "95%" if (initial_flag and (gemini_res.get("verified") or len(discovered_flags) > 0)) else "45%"

        # Backend Telemetry Log (As Required)
        print("\n" + "=" * 60)
        print("MODEL PIPELINE\n")
        print(f"Evidence:\n{filename}\n")
        print(f"Nemotron:\n{nemotron_res.get('status', 'skipped')}\n")
        print(f"Gemini:\n{gemini_res.get('status', 'skipped')}\n")
        print(f"Consensus:\n{consensus_status}\n")
        print("=" * 60 + "\n")

        # Flag Status Section
        if initial_flag and (gemini_res.get("verified", True) or len(discovered_flags) > 0):
            flag_status_str = f"FLAG FOUND:\n{initial_flag}"
        else:
            flag_status_str = (
                "FLAG NOT VERIFIED\n\n"
                "- Evidence is partial or encrypted without required key.\n"
                "- Perform further multi-stage forensic analysis on target files."
            )

        recovered_artifacts_list = []
        if discovered_flags:
            recovered_artifacts_list.append(f"- Extracted Flag: `{discovered_flags[0]}`")
        if extracted_data.get("password_candidates"):
            recovered_artifacts_list.append(f"- Recovered Passphrase/PIN: `{', '.join(extracted_data['password_candidates'])}`")
        if not recovered_artifacts_list:
            recovered_artifacts_list.append("- No confirmed plaintext flags in current pass.")

        recovered_artifacts_str = "\n".join(recovered_artifacts_list)

        # Final Synthesized Response in exact requested format:
        report = (
            f"CYBERQWEN HYBRID REPORT\n\n"
            f"Evidence:\n"
            f"- Target Package: `{filename}`\n"
            f"- Discovered Files: {', '.join([f'`{fn}`' for fn in extracted_data['file_names']])}\n"
            f"- Pipeline Mode: `{mode.upper()}` (CyberQwen + Nemotron + Gemini)\n\n"
            f"Analysis:\n"
            f"{nemotron_res.get('analysis', 'Forensic inspection of archive headers, audio streams, and text clues completed.')}\n\n"
            f"Recovered Artifacts:\n"
            f"{recovered_artifacts_str}\n\n"
            f"Flag Status:\n\n"
            f"{flag_status_str}\n\n"
            f"Confidence:\n"
            f"{confidence_pct}"
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 1)

        return {
            "filename": filename,
            "mode": mode,
            "response": report,
            "nemotron_status": nemotron_res.get("status"),
            "gemini_status": gemini_res.get("status"),
            "consensus": consensus_status,
            "final_flag": initial_flag if consensus_status == "verified" else None,
            "latency_ms": elapsed_ms,
            "tokens": len(report.split())
        }
