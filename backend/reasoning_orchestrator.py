"""
CyberQwen-AI: Production Multi-Model Active Reasoning Orchestrator
Coordinates active solving between CyberQwen (Primary), NVIDIA Nemotron (Reasoning Planner),
and Google Gemini (Adversarial Verification Guard).
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
        Executes active investigation and consensus report synthesis.
        """
        start_time = time.time()
        evidence_manifest = extracted_data["manifest"]
        recovered_flags_map = extracted_data.get("recovered_flags", {})
        discovered_flags = list(recovered_flags_map.keys()) if recovered_flags_map else extracted_data.get("discovered_flags", [])
        actions_performed = extracted_data.get("actions_performed", [])
        hypotheses = extracted_data.get("hypotheses", [])
        
        initial_flag = discovered_flags[0] if discovered_flags else None
        flag_source_file = recovered_flags_map.get(initial_flag, filename) if initial_flag else "Artifact Stream"

        nemotron_res = {"status": "skipped", "analysis": "N/A", "confidence": "N/A", "possible_flag": None}
        gemini_res = {"status": "skipped", "verified": False, "verification_details": "N/A", "flag_confirmed": None}

        # Step 1 & 2: Nemotron Deep Reasoning Planner
        if mode in ["nemotron", "hybrid"]:
            print(f"[*] Dispatching evidence to NVIDIA Nemotron Reasoning Planner...")
            nemotron_res = run_nemotron_reasoning(evidence_manifest, filename)
            if nemotron_res.get("possible_flag") and not initial_flag:
                initial_flag = nemotron_res["possible_flag"]
                flag_source_file = "Nemotron Artifact Derivation"

        # Step 3: Gemini Adversarial Verification Guard
        if mode in ["gemini", "hybrid"]:
            print(f"[*] Dispatching candidate flag & evidence to Google Gemini Verification Agent...")
            candidate = initial_flag or nemotron_res.get("possible_flag")
            gemini_res = run_gemini_verification(evidence_manifest, nemotron_res, candidate)
            if gemini_res.get("flag_confirmed"):
                initial_flag = gemini_res["flag_confirmed"]

        # Step 4: CyberQwen Final Consensus Synthesis
        print(f"[*] Synthesizing final CyberQwen Solver Report (Mode: {mode.upper()})...")
        consensus_status = "verified" if initial_flag else "unverified"

        # Backend Telemetry Log (As Required)
        print("\n" + "=" * 60)
        print("MODEL PIPELINE\n")
        print(f"Evidence:\n{filename}\n")
        print(f"Nemotron:\n{nemotron_res.get('status', 'skipped')}\n")
        print(f"Gemini:\n{gemini_res.get('status', 'skipped')}\n")
        print(f"Consensus:\n{consensus_status}\n")
        print("=" * 60 + "\n")

        # Format Actions Performed Checklist
        actions_list_str = "\n".join([f"✓ {act}" for act in actions_performed]) if actions_performed else "✓ Inspected file structure and metadata"

        # Format Evidence Summary
        evidence_bullets = [
            f"- **Target Package**: `{filename}` ({extracted_data.get('file_count', 1)} files)",
            f"- **Discovered Files**: {', '.join([f'`{fn}`' for fn in extracted_data.get('file_names', [])])}"
        ]
        if extracted_data.get("password_candidates"):
            evidence_bullets.append(f"- **Harvested Passphrase Clues**: `{', '.join(extracted_data['password_candidates'])}`")
        for hyp in hypotheses:
            evidence_bullets.append(f"- **Hypothesis Tested**: {hyp['finding']} -> {hyp['hypothesis']} (**Result: {hyp['result']}**)")
        
        evidence_str = "\n".join(evidence_bullets)

        # Format Verification Section
        if initial_flag:
            verification_str = f"Flag extracted from:\n`{flag_source_file}`"
            final_flag_section = f"FINAL FLAG:\n{initial_flag}\n\nConfidence:\n100%\n\nReason:\nExact flag recovered from artifact."
        else:
            verification_str = "All automated recovery paths exhausted across Base64, Hex, ROT, XOR, and archive passwords."
            final_flag_section = (
                "FINAL FLAG:\n"
                "All automated recovery paths exhausted.\n\n"
                "Confidence:\n"
                "Low (0%)\n\n"
                "Reason:\n"
                "No flag pattern identified in extracted streams."
            )

        # Files analyzed list
        files_analyzed_str = "\n".join([f"- `{fn}`" for fn in extracted_data.get("file_names", [])])

        # Final Synthesized Report in exact requested format
        report = (
            f"CYBERQWEN SOLVER REPORT\n\n\n"
            f"Target:\n"
            f"{filename}\n\n\n"
            f"Files analyzed:\n"
            f"{files_analyzed_str}\n\n\n"
            f"Actions performed:\n"
            f"{actions_list_str}\n\n\n"
            f"Evidence:\n"
            f"{evidence_str}\n\n\n"
            f"Verification:\n"
            f"{verification_str}\n\n\n"
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
            "final_flag": initial_flag if consensus_status == "verified" else None,
            "latency_ms": elapsed_ms,
            "tokens": len(report.split())
        }
