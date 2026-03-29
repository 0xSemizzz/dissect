"""
Parses and validates JSON responses from AI.
Retries on parse failure.
"""
import json
import re
from typing import Optional, Dict, Any
from json_repair import repair_json


# Required fields in AI response
REQUIRED_FIELDS = [
    "script_type",
    "summary",
    "what_it_does_steps",
    "suspicious_behaviors",
    "benign_behaviors",
    "obfuscation_detected",
    "risk_level",
    "risk_reasoning",
    "verdict",
    "confidence",
]

VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}
VALID_SCRIPT_TYPES = {"PowerShell", "Bash", "Batch", "Python", "VBScript", "Other"}


class ParseError(Exception):
    """Raised when AI response cannot be parsed or validated."""
    pass


def parse_ai_response(raw_text: str) -> Dict[str, Any]:
    """
    Parse raw AI response text into validated JSON.
    
    Args:
        raw_text: Raw response from AI API
        
    Returns:
        Validated dictionary with analysis results
        
    Raises:
        ParseError: If parsing or validation fails
    """
    # Try to extract JSON from the response
    json_str = _extract_json(raw_text)
    
    if not json_str:
        raise ParseError("No JSON found in response")
    
    # Repair common JSON issues (unescaped quotes, missing commas, etc.)
    json_str = repair_json(json_str, return_objects=False)
    
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}")
    
    # Validate required fields
    _validate_fields(data)
    
    return data


def _extract_json(text: str) -> Optional[str]:
    """
    Extract JSON object from text that may contain markdown or other content.
    
    Handles cases like:
    - ```json {...} ```
    - ``` {...} ```
    - Plain JSON
    """
    # Try to find JSON between markdown code fences
    match = re.search(r'```(?:json)?\s*({.*?})\s*```', text, re.DOTALL)
    if match:
        return match.group(1)
    
    # Try to find JSON object directly (from first { to last })
    start = text.find('{')
    end = text.rfind('}') + 1
    
    if start != -1 and end > start:
        return text[start:end]
    
    return None


def _validate_fields(data: Dict[str, Any]) -> None:
    """Validate that all required fields are present and valid."""
    missing = [field for field in REQUIRED_FIELDS if field not in data]
    if missing:
        raise ParseError(f"Missing required fields: {', '.join(missing)}")
    
    # Validate enum fields
    if data.get("risk_level") not in VALID_RISK_LEVELS:
        raise ParseError(f"Invalid risk_level: {data.get('risk_level')}")
    
    if data.get("confidence") not in VALID_CONFIDENCE_LEVELS:
        raise ParseError(f"Invalid confidence: {data.get('confidence')}")
    
    if data.get("script_type") not in VALID_SCRIPT_TYPES:
        raise ParseError(f"Invalid script_type: {data.get('script_type')}")
    
    # Validate list fields
    if not isinstance(data.get("what_it_does_steps"), list):
        raise ParseError("what_it_does_steps must be a list")
    
    if not isinstance(data.get("suspicious_behaviors"), list):
        raise ParseError("suspicious_behaviors must be a list")
    
    if not isinstance(data.get("benign_behaviors"), list):
        raise ParseError("benign_behaviors must be a list")
