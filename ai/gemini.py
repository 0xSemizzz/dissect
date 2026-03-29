"""
Gemini API client.
"""
import google.generativeai as genai
from typing import Dict, Any, Optional
from ai.prompts import SYSTEM_PROMPT, build_user_prompt
from ai.parser import parse_ai_response, ParseError


class GeminiClient:
    """Client for Google's Gemini API."""
    
    def __init__(self, api_key: str):
        """Initialize the Gemini client."""
        genai.configure(api_key=api_key)
        # Use Gemini 2.0 Flash - fast and free
        self.model = genai.GenerativeModel("gemini-2.0-flash")
    
    async def analyze(
        self,
        script: str,
        enrichment: Optional[Dict[str, Any]] = None,
        obfuscation_flags: Optional[list] = None,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """
        Send script to Gemini for analysis.
        
        Args:
            script: The script content to analyze
            enrichment: External API lookup results (Phase 2+)
            obfuscation_flags: Static obfuscation detection results
            max_retries: Number of retry attempts on parse failure
            
        Returns:
            Parsed and validated analysis results
            
        Raises:
            Exception: If analysis fails after all retries
        """
        enrichment = enrichment or {}
        obfuscation_flags = obfuscation_flags or []
        
        user_prompt = build_user_prompt(script, enrichment, obfuscation_flags)
        
        last_error = None
        
        for attempt in range(max_retries + 1):
            try:
                # Generate response
                response = await self._generate_response(
                    system_prompt=SYSTEM_PROMPT,
                    user_prompt=user_prompt
                )
                
                # Parse and validate
                result = parse_ai_response(response)
                return result
                
            except ParseError as e:
                last_error = e
                # Retry on parse failure
                continue
            except Exception as e:
                # Non-retryable error
                raise
        
        # All retries exhausted
        raise ParseError(f"Failed to parse AI response after {max_retries + 1} attempts: {last_error}")
    
    async def _generate_response(
        self,
        system_prompt: str,
        user_prompt: str
    ) -> str:
        """Generate response from Gemini."""
        # Combine system and user prompts
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        
        # Generate response (async via run_in_executor)
        import asyncio
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.model.generate_content(full_prompt)
        )
        
        return response.text
    
    async def explain_obfuscation(
        self,
        script: str,
        flags: list
    ) -> Optional[str]:
        """
        Get plain English explanation of obfuscation techniques.
        
        Returns None if explanation cannot be generated.
        """
        from ai.prompts import DEOBFUSCATION_PROMPT
        
        prompt = DEOBFUSCATION_PROMPT.format(
            script=script[:2000],  # Truncate to avoid token limits
            flags="\n".join(flags)
        )
        
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.model.generate_content(prompt)
            )
            return response.text
        except Exception:
            return None
