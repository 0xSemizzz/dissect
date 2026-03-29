"""
Static obfuscation detection using pattern matching.
No AI — pure regex and string analysis.
"""
import re
from typing import List, Dict, Any


# Obfuscation patterns with descriptions
OBFUSCATION_PATTERNS = [
    {
        "name": "PowerShell backtick obfuscation",
        "pattern": r'`\S',
        "description": "Backtick characters used to escape and hide command parts",
    },
    {
        "name": "Character code array",
        "pattern": r'\[\s*(?:char|byte)\s*\]?\s*\d+(?:\s*,\s*\d+)+',
        "description": "ASCII character codes used to hide strings",
    },
    {
        "name": "Base64 decode execution",
        "pattern": r'(?:FromBase64String|base64_decode|atob).*?(?:IEX|Invoke-Expression|eval|exec)',
        "description": "Base64 decoded content is executed directly",
    },
    {
        "name": "XOR encoding",
        "pattern": r'(?:XOR|xor|\^)\s*(?:0x[0-9a-fA-F]+|\d+)',
        "description": "XOR encryption used to hide data",
    },
    {
        "name": "Reversed string",
        "pattern": r'-join\s*\[[^\]]*\]\s*\[[^\]]*\]\[Array\]::Reverse',
        "description": "String is reversed to evade detection",
    },
    {
        "name": "Hex encoded string",
        "pattern": r'0x(?:[0-9a-fA-F]{2,})+',
        "description": "Hexadecimal encoding used to hide strings",
    },
    {
        "name": "String concatenation obfuscation",
        "pattern": r'["\'][^"\']{1,3}["\']\s*\+\s*["\'][^"\']{1,3}["\']\s*\+',
        "description": "Strings split and concatenated to evade detection",
    },
    {
        "name": "Environment variable expansion",
        "pattern": r'%[A-Za-z_][A-Za-z0-9_]*%',
        "description": "Environment variables used to construct paths/commands",
    },
    {
        "name": "PowerShell -EncodedCommand",
        "pattern": r'-[eE]ncodedCommand|-[eE]c\s',
        "description": "EncodedCommand parameter used to hide script content",
    },
    {
        "name": "Unusual whitespace",
        "pattern": r'[ \t]{5,}|[\x0b\x0c]+',
        "description": "Excessive or unusual whitespace to disrupt pattern matching",
    },
    {
        "name": "Unicode escape sequences",
        "pattern": r'\\u[0-9a-fA-F]{4}',
        "description": "Unicode escapes used to hide characters",
    },
    {
        "name": "Format operator obfuscation",
        "pattern": r'-f\s*["\'][^"\']*["\'].*,\s*["\'][^"\']*["\']',
        "description": "Format operator used to construct strings dynamically",
    },
]


def detect_obfuscation(script: str) -> Dict[str, Any]:
    """
    Detect obfuscation techniques in a script.
    
    Args:
        script: The script content
        
    Returns:
        Dictionary with detection results:
        {
            "obfuscation_detected": bool,
            "flags": list of flag dictionaries
        }
    """
    flags = []
    
    for pattern_info in OBFUSCATION_PATTERNS:
        matches = re.findall(pattern_info["pattern"], script, re.IGNORECASE)
        if matches:
            flags.append({
                "name": pattern_info["name"],
                "description": pattern_info["description"],
                "match_count": len(matches),
                "sample": _truncate(str(matches[0]), 50),
            })
    
    return {
        "obfuscation_detected": len(flags) > 0,
        "flags": flags,
        "flag_count": len(flags),
    }


def _truncate(text: str, max_length: int) -> str:
    """Truncate text to max length with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def get_obfuscation_summary(flags: List[Dict[str, Any]]) -> str:
    """
    Generate a human-readable summary of obfuscation flags.
    
    For Phase 1, returns a simple string.
    """
    if not flags:
        return "No obfuscation detected"
    
    techniques = [flag["name"] for flag in flags]
    return f"Obfuscation detected: {', '.join(techniques)}"
