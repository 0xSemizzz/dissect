"""
Orchestrates the full analysis pipeline.
"""
from typing import Dict, Any, Optional
from core.extractor import extract_all, detect_script_type, compute_script_hash
from core.obfuscation import detect_obfuscation
from ai.groq import GroqClient


class AnalysisResult:
    def __init__(
        self,
        script_hash: str,
        script_type: str,
        ai_analysis: Dict[str, Any],
        obfuscation: Dict[str, Any],
        extracted: Dict[str, Any],
        errors: Optional[list] = None
    ):
        self.script_hash = script_hash
        self.script_type = script_type
        self.ai_analysis = ai_analysis
        self.obfuscation = obfuscation
        self.extracted = extracted
        self.errors = errors or []
    
    @property
    def risk_level(self) -> str:
        return self.ai_analysis.get("risk_level", "UNKNOWN")
    
    @property
    def verdict(self) -> str:
        return self.ai_analysis.get("verdict", "Analysis unavailable")
    
    @property
    def summary(self) -> str:
        return self.ai_analysis.get("summary", "")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "script_hash": self.script_hash,
            "script_type": self.script_type,
            "ai_analysis": self.ai_analysis,
            "obfuscation": self.obfuscation,
            "extracted": self.extracted,
            "errors": self.errors,
        }


async def analyze_script(
    script: str,
    groq_client: GroqClient,
    enrichment: Optional[Dict[str, Any]] = None,
) -> AnalysisResult:
    errors = []
    enrichment = enrichment or {}
    
    validation_error = _validate_input(script)
    if validation_error:
        return AnalysisResult(
            script_hash="invalid",
            script_type="Unknown",
            ai_analysis={"error": validation_error},
            obfuscation={"obfuscation_detected": False, "flags": []},
            extracted={},
            errors=[validation_error],
        )
    
    extracted = extract_all(script)
    script_type = detect_script_type(script)
    script_hash = compute_script_hash(script)
    
    obfuscation = detect_obfuscation(script)
    obfuscation_flags = [flag["name"] for flag in obfuscation["flags"]]
    
    try:
        ai_analysis = await groq_client.analyze(
            script=script,
            enrichment=enrichment,
            obfuscation_flags=obfuscation_flags,
        )
    except Exception as e:
        errors.append(f"AI analysis failed: {str(e)}")
        ai_analysis = {
            "script_type": script_type,
            "summary": "AI analysis temporarily unavailable.",
            "what_it_does_steps": [],
            "suspicious_behaviors": [],
            "benign_behaviors": [],
            "obfuscation_detected": obfuscation["obfuscation_detected"],
            "risk_level": "UNKNOWN",
            "risk_reasoning": "Could not complete analysis.",
            "verdict": "INVESTIGATE FURTHER — AI analysis unavailable. Try again or consult a security professional.",
            "confidence": "LOW",
            "confidence_reason": "AI service unavailable.",
        }
    
    return AnalysisResult(
        script_hash=script_hash,
        script_type=script_type,
        ai_analysis=ai_analysis,
        obfuscation=obfuscation,
        extracted=extracted,
        errors=errors,
    )


def _validate_input(script: str) -> Optional[str]:
    if not script or not script.strip():
        return "Empty script provided"
    
    if len(script) > 50 * 1024:
        return "Script too large (max 50KB)"
    
    try:
        script.encode('utf-8')
    except UnicodeEncodeError:
        return "Script contains invalid characters"
    
    return None
