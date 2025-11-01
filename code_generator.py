"""Code Generator Module - Generates Python code using LLM providers."""
import json
import requests
from typing import Optional, Dict, Any

from parser import ProblemSpec
from logger import logger
from config import Config
from utils import validate_python_syntax, contains_dangerous_patterns
from gemini_provider import GeminiProvider

class CodeGenerator:
    """Generates Python code using LLM (Gemini or Ollama)."""
    
    def __init__(self):
        # Initialize both providers
        self.gemini = GeminiProvider()
        self.ollama_url = f"{Config.OLLAMA_HOST}/api/generate"
        self.ollama_model = Config.OLLAMA_MODEL
        
        # Determine which provider to use
        self.use_gemini = (Config.CODE_LLM_PROVIDER == "gemini" and self.gemini.is_available())
        
        if self.use_gemini:
            logger.info("Code generator using Gemini API")
            self.temperature = Config.GEMINI_TEMPERATURE
            self.max_tokens = Config.GEMINI_MAX_TOKENS
        else:
            logger.info("Code generator using Ollama", reason="Gemini not available or not configured")
            self.temperature = Config.OLLAMA_TEMPERATURE
            self.max_tokens = Config.OLLAMA_MAX_TOKENS
    
    def generate(self, spec: ProblemSpec, test_code: str = None, 
                 feedback: str = None) -> tuple[str, Dict[str, Any]]:
        """Generate Python implementation from specification.
        
        Args:
            spec: Problem specification
            test_code: Generated test code for context
            feedback: Failure feedback for refinement (optional)
            
        Returns:
            Tuple of (generated_code, metadata)
        """
        logger.info("Generating code", 
                   function=spec.function_name,
                   has_feedback=feedback is not None,
                   provider="Gemini" if self.use_gemini else "Ollama")
        
        # Build prompt
        prompt = self._build_prompt(spec, test_code, feedback)
        
        # Generate code using appropriate provider
        if self.use_gemini:
            code = self.gemini.generate(prompt)
            provider_name = "gemini"
            model_name = Config.GEMINI_MODEL
        else:
            code = self._call_ollama(prompt)
            provider_name = "ollama"
            model_name = self.ollama_model
        
        if not code:
            error_msg = f"Failed to generate code using {provider_name}. LLM did not return any code."
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        # Extract code from response
        code = self._extract_code(code)
        
        # Validate syntax
        is_valid, error = validate_python_syntax(code)
        if not is_valid:
            logger.warning("Generated code has syntax errors", error=error)
            code = self._fix_syntax_errors(code)
        
        # Security check
        has_danger, violations = contains_dangerous_patterns(code)
        if has_danger:
            logger.warning("Generated code has security issues", 
                          violations=violations)
            code = self._remove_dangerous_patterns(code)
        
        metadata = {
            "method": f"{provider_name}_{model_name}",
            "provider": provider_name,
            "model": model_name,
            "temperature": self.temperature,
            "has_feedback": feedback is not None,
            "lines": len(code.split('\n'))
        }
        
        logger.info("Generated code successfully", **metadata)
        
        return code, metadata
        
        logger.info("Generated code successfully", **metadata)
        
        return code, metadata
    
    def _build_prompt(self, spec: ProblemSpec, test_code: str = None,
                     feedback: str = None) -> str:
        """Build prompt for code generation."""
        if feedback:
            # Enhanced refinement prompt with detailed feedback
            prompt = f"""TASK: Fix the failing Python implementation based on detailed test failure analysis.

{'=' * 80}
TEST FAILURE ANALYSIS:
{'=' * 80}
{feedback}

{'=' * 80}
SPECIFICATION:
{'=' * 80}
Function Name: {spec.function_name}
Description: {spec.description}

Parameters:
"""
            for param in spec.parameters:
                prompt += f"  - {param.name}: {param.type_hint}"
                if param.description:
                    prompt += f" - {param.description}"
                prompt += "\n"
            
            prompt += f"\nReturn Type: {spec.return_type}\n"
            
            if spec.constraints:
                prompt += "\nConstraints:\n"
                for constraint in spec.constraints:
                    prompt += f"  - {constraint}\n"
            
            prompt += f"""
{'=' * 80}
CRITICAL REQUIREMENTS:
{'=' * 80}
1. Function name MUST be EXACTLY '{spec.function_name}' (case-sensitive)
2. Fix ALL issues identified in the failure analysis above
3. Handle ALL edge cases mentioned in the failing tests
4. Ensure proper input validation (raise ValueError/TypeError when appropriate)
5. Test your logic mentally with the failing test cases before generating
6. Use proper type hints matching the specification
7. Include docstring explaining the logic
8. Follow PEP 8 style guidelines

{'=' * 80}
RESPONSE FORMAT:
{'=' * 80}
Generate ONLY the complete, corrected Python code.
Do NOT include explanations, test code, or examples.
Start directly with imports (if needed) or the function/class definition.

Generate the complete corrected implementation now:"""
        else:
            # Initial generation prompt
            prompt = f"""Generate a Python function with the following specification:

Function Name: {spec.function_name}
Description: {spec.description}

Parameters:
"""
            for param in spec.parameters:
                prompt += f"  - {param.name}: {param.type_hint} - {param.description}\n"
            
            prompt += f"\nReturn Type: {spec.return_type}\n"
            
            if spec.constraints:
                prompt += "\nConstraints:\n"
                for constraint in spec.constraints:
                    prompt += f"  - {constraint}\n"
            
            if spec.examples:
                prompt += "\nExamples:\n"
                for ex in spec.examples[:3]:
                    prompt += f"  Input: {ex.get('input')} -> Output: {ex.get('output')}\n"
            
            if spec.edge_cases:
                prompt += "\nEdge Cases to Handle:\n"
                for edge in spec.edge_cases[:3]:
                    prompt += f"  - {edge}\n"
            
            prompt += f"""
Requirements:
- CRITICAL: The function name MUST be exactly '{spec.function_name}' (not any other name)
- Implement ONLY the function {spec.function_name}
- Use proper type hints matching the specification above
- Handle edge cases gracefully
- Follow PEP 8 style guide
- Include a comprehensive docstring
- Do NOT include test code or examples
- Do NOT generate any other functions
- Generate complete, working implementation

Generate ONLY the Python function '{spec.function_name}':"""
        
        return prompt
    
    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Call Ollama API to generate code.
        
        Args:
            prompt: Generation prompt
            
        Returns:
            Generated code or None if failed
        """
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "temperature": self.temperature,
                "stream": False,
                "options": {
                    "num_predict": self.max_tokens,
                    "top_p": 0.9,
                    "top_k": 40,
                }
            }
            
            logger.debug("Calling Ollama API", model=self.model)
            
            response = requests.post(
                self.ollama_url,
                json=payload,
                timeout=120  # Increased to 2 minutes
            )
            
            if response.status_code == 200:
                result = response.json()
                generated_text = result.get("response", "")
                logger.debug("Ollama response received", 
                           length=len(generated_text))
                return generated_text
            else:
                logger.error("Ollama API error", 
                           status_code=response.status_code,
                           error=response.text)
                return None
                
        except requests.exceptions.Timeout:
            logger.error("Ollama API timeout")
            return None
        except Exception as e:
            logger.error("Ollama API exception", error=str(e))
            return None
    
    def _extract_code(self, response: str) -> str:
        """Extract Python code from Ollama response.
        
        Args:
            response: Raw Ollama response
            
        Returns:
            Extracted code
        """
        # Log raw response for debugging
        logger.debug("Extracting code from response",
                    response_length=len(response),
                    has_code_block="```" in response)
        
        # Remove markdown code blocks
        code = response
        
        # Extract from ```python blocks
        if "```python" in code:
            start = code.find("```python") + len("```python")
            end = code.find("```", start)
            if end != -1:
                code = code[start:end].strip()
            else:
                logger.warning("Unclosed ```python block detected")
        elif "```" in code:
            start = code.find("```") + 3
            end = code.find("```", start)
            if end != -1:
                code = code[start:end].strip()
        
        # Remove any explanatory text before the function/class
        lines = code.split('\n')
        func_start = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Look for function or class definitions at module level (no indentation)
            if (stripped.startswith('def ') or stripped.startswith('class ')) and line[0] not in (' ', '\t'):
                func_start = i
                break
        
        if func_start > 0:
            code = '\n'.join(lines[func_start:])
        
        # Add necessary typing imports if type hints are used
        code = self._ensure_typing_imports(code)
        
        return code.strip()
    
    def _ensure_typing_imports(self, code: str) -> str:
        """Add typing imports if type hints are used but not imported.
        
        Args:
            code: Generated code
            
        Returns:
            Code with typing imports added if needed
        """
        # Check if typing hints are used
        typing_hints = []
        if 'Any' in code and 'from typing import' not in code:
            typing_hints.append('Any')
        if 'List[' in code and 'from typing import' not in code:
            typing_hints.append('List')
        if 'Dict[' in code and 'from typing import' not in code:
            typing_hints.append('Dict')
        if 'Optional[' in code and 'from typing import' not in code:
            typing_hints.append('Optional')
        if 'Tuple[' in code and 'from typing import' not in code:
            typing_hints.append('Tuple')
        if 'Union[' in code and 'from typing import' not in code:
            typing_hints.append('Union')
        
        # Add import if needed
        if typing_hints:
            import_line = f"from typing import {', '.join(set(typing_hints))}\n\n"
            code = import_line + code
            logger.debug("Added typing imports", imports=typing_hints)
        
        return code
    
    def _fix_syntax_errors(self, code: str) -> str:
        """Attempt to fix common syntax errors.
        
        Args:
            code: Code with syntax errors
            
        Returns:
            Fixed code (best effort)
        """
        # Try to fix common issues
        lines = code.split('\n')
        fixed_lines = []
        
        for line in lines:
            # Fix missing colons
            if line.strip().startswith(('if ', 'elif ', 'else', 'for ', 'while ', 'def ', 'class ')):
                if not line.rstrip().endswith(':'):
                    line = line.rstrip() + ':'
            fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)
    
    def _remove_dangerous_patterns(self, code: str) -> str:
        """Remove dangerous patterns from code.
        
        Args:
            code: Code with potential security issues
            
        Returns:
            Sanitized code
        """
        # Remove dangerous imports and calls
        lines = code.split('\n')
        safe_lines = []
        
        for line in lines:
            # Skip dangerous imports
            if any(danger in line for danger in Config.BLOCKED_IMPORTS):
                continue
            # Skip eval/exec calls
            if any(func in line for func in ['eval(', 'exec(', '__import__(']):
                continue
            safe_lines.append(line)
        
        return '\n'.join(safe_lines)
