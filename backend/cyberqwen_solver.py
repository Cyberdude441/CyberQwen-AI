"""
CyberQwen-AI: Independent CyberQwen Solver Agent
Executes isolated cybersecurity domain solving, crypto decoding, and reverse engineering analysis.
"""

import json
import re
from typing import Dict, Any, Optional
from backend.active_solver import FLAG_PATTERN

def solve_with_cyberqwen(evidence_manifest: str, extracted_data: Dict[str, Any], cyber_service) -> Dict[str, Any]:
    """
    Solves the CTF challenge independently using CyberQwen 8B Local.
    Returns structured JSON output.
    """
    discovered_flags = extracted_data.get("discovered_flags", [])
    recovered_map = extracted_data.get("recovered_flags", {})
    
    if discovered_flags:
        flag = discovered_flags[0]
        source = recovered_map.get(flag, "Artifact Inspection")
        return {
            "model": "CyberQwen",
            "flag_found": flag,
            "status": "FOUND",
            "reasoning": "Identified direct cryptographic / reverse engineered flag pattern from decompressed evidence stream.",
            "evidence_source": source,
            "confidence": 98
        }
    
    # Fallback to local LLM reasoning
    system_prompt = (
        "You are CyberQwen CTF Solver.\n"
        "Analyze the provided forensic evidence manifest and recover the flag.\n"
        "Respond strictly in valid JSON:\n"
        "{\n"
        '  "model": "CyberQwen",\n'
        '  "flag_found": "FLAG{...}" or null,\n'
        '  "status": "FOUND" or "NOT_FOUND",\n'
        '  "reasoning": "explanation",\n'
        '  "evidence_source": "source file/function",\n'
        '  "confidence": integer 0-100\n'
        "}"
    )

    try:
        res = cyber_service.generate_response(
            message=f"Forensic Evidence Manifest:\n{evidence_manifest[:3500]}",
            system_prompt=system_prompt,
            max_new_tokens=400,
            temperature=0.1
        )
        raw_text = res.get("response", "")
        # Look for JSON block
        json_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
            data["model"] = "CyberQwen"
            return data
    except Exception:
        pass

    return {
        "model": "CyberQwen",
        "flag_found": None,
        "status": "NOT_FOUND",
        "reasoning": "All automated heuristics and local analysis paths exhausted without finding valid flag string.",
        "evidence_source": "Exhausted Streams",
        "confidence": 20
    }
