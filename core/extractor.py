"""
Extracts URLs, IPs, hashes, file paths from scripts using regex.
Pure static analysis — no AI.
"""
import re
import hashlib
from typing import Dict, List, Any


# Regex patterns for extraction
PATTERNS = {
    # URLs: http, https, ftp
    "url": re.compile(
        r'(?:https?|ftp)://[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    ),
    # IPv4 addresses
    "ip": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    # File paths (Windows and Unix)
    "filepath": re.compile(
        r'(?:[A-Za-z]:\\[^\s<>"|?*]+|[A-Za-z]:\\/|[\\/][^\s<>"|?*]+)',
        re.IGNORECASE
    ),
    # Base64 encoded strings (min 20 chars, only base64 chars)
    "base64": re.compile(
        r'[A-Za-z0-9+/]{20,}={0,2}'
    ),
    # SHA256 hashes (64 hex chars)
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    # SHA1 hashes (40 hex chars)
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    # MD5 hashes (32 hex chars)
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
}

# Script type detection patterns
SCRIPT_TYPE_PATTERNS = {
    "PowerShell": [r'\$\w+', r'Invoke-', r'Get-', r'Set-', r'New-Object', r'powershell'],
    "Bash": [r'#!/bin/bash', r'\$\{?\w+\}?', r'echo\s', r'grep\s', r'curl\s', r'wget\s'],
    "Batch": [r'@echo', r'%\w+%', r'goto\s', r':\w+', r'call\s'],
    "Python": [r'#!/usr/bin/python', r'import\s+\w+', r'def\s+\w+\(', r'print\s*\('],
    "VBScript": [r'Dim\s+\w+', r'Set\s+\w+\s*=', r'Function\s+\w+', r'WScript\.'],
}


def extract_all(script: str) -> Dict[str, List[str]]:
    """
    Extract all indicators from a script.
    
    Args:
        script: The script content
        
    Returns:
        Dictionary with lists of extracted indicators
    """
    results = {
        "urls": list(set(PATTERNS["url"].findall(script))),
        "ips": list(set(PATTERNS["ip"].findall(script))),
        "filepaths": list(set(PATTERNS["filepath"].findall(script))),
        "base64_strings": list(set(PATTERNS["base64"].findall(script))),
        "hashes": {
            "sha256": list(set(PATTERNS["sha256"].findall(script))),
            "sha1": list(set(PATTERNS["sha1"].findall(script))),
            "md5": list(set(PATTERNS["md5"].findall(script))),
        },
    }
    
    # Flatten hashes
    all_hashes = []
    for hash_list in results["hashes"].values():
        all_hashes.extend(hash_list)
    results["hashes"] = all_hashes
    
    return results


def detect_script_type(script: str) -> str:
    """
    Detect the script type based on content patterns.
    
    Returns:
        Script type string (PowerShell, Bash, Batch, Python, VBScript, or Other)
    """
    scores = {script_type: 0 for script_type in SCRIPT_TYPE_PATTERNS}
    
    for script_type, patterns in SCRIPT_TYPE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, script, re.IGNORECASE | re.MULTILINE):
                scores[script_type] += 1
    
    # Return highest scoring type
    best_match = max(scores, key=scores.get)
    if scores[best_match] > 0:
        return best_match
    
    return "Other"


def compute_script_hash(script: str) -> str:
    """
    Compute SHA256 hash of script content.
    
    Used for caching and duplicate detection.
    """
    return hashlib.sha256(script.encode('utf-8')).hexdigest()


def extract_indicators_for_enrichment(script: str) -> Dict[str, Any]:
    """
    Extract indicators that will be enriched in Phase 2.
    
    Returns structured data ready for enrichment APIs.
    """
    extracted = extract_all(script)
    
    return {
        "urls": [{"url": url, "virustotal": {}, "urlscan": {}} for url in extracted["urls"]],
        "ips": [{"ip": ip, "ipinfo": {}, "shodan": {}} for ip in extracted["ips"]],
        "hashes": [{"hash": h, "malwarebazaar": {}, "virustotal": {}} for h in extracted["hashes"]],
    }
