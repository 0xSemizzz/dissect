"""
Groq API client.
"""
from groq import Groq
from typing import Dict, Any, Optional
from ai.prompts import SYSTEM_PROMPT, build_user_prompt
from ai.parser import parse_ai_response, ParseError


class GroqClient:
    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"
    
    async def analyze(
        self,
        script: str,
        enrichment: Optional[Dict[str, Any]] = None,
        obfuscation_flags: Optional[list] = None,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        enrichment = enrichment or {}
        obfuscation_flags = obfuscation_flags or []
        
        user_prompt = build_user_prompt(script, enrichment, obfuscation_flags)
        last_error = None
        
        for attempt in range(max_retries + 1):
            try:
                response = await self._generate_response(
                    system_prompt=SYSTEM_PROMPT,
                    user_prompt=user_prompt
                )
                result = parse_ai_response(response)
                return result
                
            except ParseError as e:
                last_error = e
                continue
            except Exception as e:
                raise
        
        raise ParseError(f"Failed to parse AI response after {max_retries + 1} attempts: {last_error}")
    
    async def _generate_response(
        self,
        system_prompt: str,
        user_prompt: str
    ) -> str:
        import asyncio
        
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        loop = asyncio.get_event_loop()
        
        def call_groq():
            return self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=2000,
            )
        
        response = await loop.run_in_executor(None, call_groq)
        return response.choices[0].message.content
    
    async def explain_obfuscation(
        self,
        script: str,
        flags: list
    ) -> Optional[str]:
        from ai.prompts import DEOBFUSCATION_PROMPT
        import asyncio
        
        prompt = DEOBFUSCATION_PROMPT.format(
            script=script[:2000],
            flags="\n".join(flags)
        )
        
        try:
            loop = asyncio.get_event_loop()
            
            def call_groq():
                return self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=300,
                )
            
            response = await loop.run_in_executor(None, call_groq)
            return response.choices[0].message.content
        except Exception:
            return None
