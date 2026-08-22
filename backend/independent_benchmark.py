"""
CyberQwen-AI: Independent Multi-Model CTF Benchmark Engine
Runs CyberQwen, NVIDIA Nemotron, and Google Gemini as 3 completely isolated solvers,
compares results, determines consensus, and generates MULTI MODEL CTF BENCHMARK REPORT.
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, Any, List
from backend.cyberqwen_solver import solve_with_cyberqwen
from backend.nemotron_solver import solve_with_nemotron
from backend.gemini_solver import solve_with_gemini

LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)
COMPARISON_LOG_FILE = LOGS_DIR / "model_comparison.json"

class IndependentBenchmarkEngine:
    def __init__(self, cyber_service):
        self.cyber_service = cyber_service

    def run_benchmark(self, filename: str, extracted_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes 3 completely isolated solving tasks on the same evidence manifest.
        Models do NOT communicate or see each other's outputs.
        """
        start_time = time.time()
        evidence_manifest = extracted_data["manifest"]

        print("\n" + "=" * 70)
        print(f"RUNNING INDEPENDENT CTF BENCHMARK: {filename}")
        print("=" * 70)

        # 1. Agent 1: CyberQwen Solver (Isolated)
        print("[*] Dispatching Task 1: CyberQwen 8B Solver...")
        qwen_res = solve_with_cyberqwen(evidence_manifest, extracted_data, self.cyber_service)

        # 2. Agent 2: NVIDIA Nemotron Solver (Isolated)
        print("[*] Dispatching Task 2: NVIDIA Nemotron Solver...")
        nemotron_res = solve_with_nemotron(evidence_manifest, filename)

        # 3. Agent 3: Google Gemini Solver (Isolated)
        print("[*] Dispatching Task 3: Google Gemini Solver...")
        gemini_res = solve_with_gemini(evidence_manifest, filename)

        # =====================================================================
        # FINAL COMPARISON ENGINE (Does NOT solve; only compares)
        # =====================================================================
        results = [qwen_res, nemotron_res, gemini_res]

        # Check Consensus
        found_flags = [r["flag_found"] for r in results if r.get("flag_found")]
        unique_flags = set(found_flags)

        if len(unique_flags) == 1 and len(found_flags) >= 2:
            consensus_status = "CONFIRMED"
            consensus_details = f"All active models agreed on identical flag: `{list(unique_flags)[0]}`"
        elif len(unique_flags) > 1:
            consensus_status = "DISAGREEMENT"
            consensus_details = f"Models proposed conflicting flag outputs: {', '.join([f'`{f}`' for f in unique_flags])}"
        elif len(unique_flags) == 1 and len(found_flags) == 1:
            consensus_status = "CONFIRMED"
            consensus_details = f"Single model isolated recovery: `{list(unique_flags)[0]}`"
        else:
            consensus_status = "NO_FLAG_FOUND"
            consensus_details = "All models agreed that no valid flag exists in current evidence."

        # Determine Winner (Highest confidence with verified evidence)
        valid_solvers = [r for r in results if r.get("flag_found")]
        if valid_solvers:
            winner_solver = max(valid_solvers, key=lambda x: (x.get("confidence", 0), len(x.get("evidence_source", ""))))
            winner_str = f"**{winner_solver['model']}** ({winner_solver.get('confidence', 0)}% Confidence - Source: `{winner_solver.get('evidence_source', 'Verified')}`)"
        else:
            winner_solver = max(results, key=lambda x: x.get("confidence", 0))
            winner_str = f"**{winner_solver['model']}** (Consistent negative rejection)"

        # Generate Benchmark Markdown Table
        table_rows = []
        for r in results:
            flag_cell = f"`{r['flag_found']}`" if r.get("flag_found") else "*None*"
            conf_cell = f"{r.get('confidence', 0)}%"
            source_cell = f"`{r.get('evidence_source', 'N/A')}`"
            table_rows.append(f"| {r['model']} | {flag_cell} | {conf_cell} | {source_cell} |")

        table_str = "\n".join(table_rows)

        # Generate Full Benchmark Report
        report = (
            f"### MULTI MODEL CTF BENCHMARK REPORT\n\n"
            f"**Target**:\n`{filename}`\n\n"
            f"#### Results:\n\n"
            f"| Model | Flag | Confidence | Evidence |\n"
            f"| :--- | :--- | :--- | :--- |\n"
            f"{table_str}\n\n"
            f"#### Consensus:\n"
            f"**{consensus_status}**\n"
            f"{consensus_details}\n\n"
            f"#### Winner:\n"
            f"{winner_str}\n\n"
            f"---\n\n"
            f"#### Individual Model Telemetry:\n"
            f"- **CyberQwen 8B**: {qwen_res.get('reasoning', '')}\n"
            f"- **NVIDIA Nemotron**: {nemotron_res.get('reasoning', '')}\n"
            f"- **Google Gemini**: {gemini_res.get('reasoning', '')}"
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 1)

        # Save to logs/model_comparison.json
        comparison_record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target": filename,
            "elapsed_ms": elapsed_ms,
            "consensus": consensus_status,
            "winner": winner_solver["model"],
            "models": {
                "CyberQwen": qwen_res,
                "Nemotron": nemotron_res,
                "Gemini": gemini_res
            }
        }

        try:
            existing_logs = []
            if COMPARISON_LOG_FILE.exists():
                try:
                    with open(COMPARISON_LOG_FILE, "r", encoding="utf-8") as f:
                        existing_logs = json.load(f)
                except Exception:
                    existing_logs = []
            existing_logs.append(comparison_record)
            with open(COMPARISON_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(existing_logs, f, indent=2)
            print(f"[+] Saved benchmark log to {COMPARISON_LOG_FILE}")
        except Exception as e:
            print(f"[!] Warning: Could not save comparison log: {e}")

        return {
            "filename": filename,
            "mode": "benchmark",
            "response": report,
            "consensus": consensus_status,
            "winner": winner_solver["model"],
            "results": results,
            "latency_ms": elapsed_ms,
            "tokens": len(report.split())
        }
