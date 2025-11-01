"""Prompt Parser Module - Converts natural language to structured specifications."""
import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

from logger import logger
from utils import sanitize_function_name

@dataclass
class ParameterSpec:
    """Specification for a function parameter."""
    name: str
    type_hint: str
    description: str = ""
    constraints: List[str] = None
    
    def __post_init__(self):
        if self.constraints is None:
            self.constraints = []

@dataclass
class ProblemSpec:
    """Structured specification of a coding problem."""
    problem_name: str
    function_name: str
    parameters: List[ParameterSpec]
    return_type: str
    description: str
    constraints: List[str]
    examples: List[Dict[str, Any]]
    edge_cases: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

class PromptParser:
    """Parses natural language problem descriptions into structured specifications."""
    
    def __init__(self):
        self.type_keywords = {
            "integer": "int",
            "int": "int",
            "number": "int",
            "float": "float",
            "decimal": "float",
            "string": "str",
            "str": "str",
            "text": "str",
            "boolean": "bool",
            "bool": "bool",
            "list": "List",
            "array": "List",
            "dict": "Dict",
            "dictionary": "Dict",
            "tuple": "Tuple",
            "set": "Set",
        }
        
    def parse(self, prompt: str) -> ProblemSpec:
        """Parse natural language prompt into structured specification.
        
        Args:
            prompt: Natural language problem description
            
        Returns:
            ProblemSpec object with extracted information
        """
        logger.info("Parsing prompt", prompt_length=len(prompt))
        
        # Extract problem name
        problem_name = self._extract_problem_name(prompt)
        function_name = sanitize_function_name(problem_name)
        
        # Extract description
        description = self._extract_description(prompt)
        
        # Extract parameters
        parameters = self._extract_parameters(prompt)
        
        # Extract return type
        return_type = self._extract_return_type(prompt)
        
        # Extract constraints
        constraints = self._extract_constraints(prompt)
        
        # Extract examples
        examples = self._extract_examples(prompt)
        
        # Extract edge cases
        edge_cases = self._extract_edge_cases(prompt)
        
        spec = ProblemSpec(
            problem_name=problem_name,
            function_name=function_name,
            parameters=parameters,
            return_type=return_type,
            description=description,
            constraints=constraints,
            examples=examples,
            edge_cases=edge_cases
        )
        
        logger.info("Parsed specification", 
                   function_name=function_name,
                   param_count=len(parameters),
                   example_count=len(examples))
        
        return spec
    
    def _extract_problem_name(self, prompt: str) -> str:
        """Extract problem name from prompt."""
        # Look for explicit naming - prioritize "called" and "named" patterns
        patterns = [
            r"(?:called|named)\s+['\"]?([a-zA-Z_][a-zA-Z0-9_]*)['\"]?",  # Highest priority
            r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",  # def function_name(
            r"(?:function|problem):\s*([a-zA-Z_][a-zA-Z0-9_]*)",
            r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:function|problem)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, prompt, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Special handling for data structure problems (LRU cache, Trie, etc.)
        # Check for specific data structures first (case-insensitive)
        if re.search(r'LRU|Least Recently Used.*cache', prompt, re.IGNORECASE):
            return "LRUCache"
        elif re.search(r'trie|prefix\s+tree', prompt, re.IGNORECASE):
            return "Trie"
        elif re.search(r'(?:min|max)\s+heap', prompt, re.IGNORECASE):
            heap_type = re.search(r'(min|max)\s+heap', prompt, re.IGNORECASE).group(1)
            return f"{heap_type.capitalize()}Heap"
        elif re.search(r'binary\s+search\s+tree|BST', prompt, re.IGNORECASE):
            return "BinarySearchTree"
        elif re.search(r'linked\s+list', prompt, re.IGNORECASE):
            return "LinkedList"
        
        # Extract from first line or generate generic name
        first_line = prompt.split('\n')[0].lower()
        # Skip common verbs like "design", "implement", "write", "create"
        skip_words = {'design', 'implement', 'write', 'create', 'develop', 'build', 'make', 'a', 'an', 'the', 'and', 'for', 'that'}
        words = [w for w in re.findall(r'\b[a-z]+\b', first_line) if w not in skip_words]
        if len(words) >= 2:
            return '_'.join(words[:3])
        elif len(words) == 1:
            return words[0]
        
        return "solution"
    
    def _extract_description(self, prompt: str) -> str:
        """Extract problem description."""
        # Clean up the prompt
        lines = [line.strip() for line in prompt.split('\n') if line.strip()]
        
        # Take first few meaningful lines
        description_lines = []
        for line in lines[:3]:
            if len(line) > 10:
                description_lines.append(line)
        
        return ' '.join(description_lines) if description_lines else prompt[:200]
    
    def _extract_parameters(self, prompt: str) -> List[ParameterSpec]:
        """Extract function parameters from prompt."""
        parameters = []
        
        # Look for explicit parameter definitions
        param_patterns = [
            r"(?:parameter|param|input|argument)s?:\s*([^\n]+)",
            r"(?:takes|accepts|receives)\s+(?:an?\s+)?(\w+)\s+(?:called\s+)?(\w+)",
            r"(?:given|with)\s+(?:an?\s+)?(\w+)\s+(\w+)",
        ]
        
        for pattern in param_patterns:
            matches = re.finditer(pattern, prompt, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) == 2:
                    type_str, name = match.groups()
                    type_hint = self._normalize_type(type_str)
                    parameters.append(ParameterSpec(
                        name=name.lower(),
                        type_hint=type_hint,
                        description=f"Input {name}"
                    ))
        
        # If no parameters found, infer from context
        if not parameters:
            # Look for common patterns
            if re.search(r'\b(?:list|array)\b', prompt, re.IGNORECASE):
                parameters.append(ParameterSpec(
                    name="items",
                    type_hint="List[int]",
                    description="Input list"
                ))
            elif re.search(r'\b(?:number|integer|value)\b', prompt, re.IGNORECASE):
                parameters.append(ParameterSpec(
                    name="n",
                    type_hint="int",
                    description="Input number"
                ))
            elif re.search(r'\b(?:string|text)\b', prompt, re.IGNORECASE):
                parameters.append(ParameterSpec(
                    name="s",
                    type_hint="str",
                    description="Input string"
                ))
        
        # Default to single parameter if still empty
        if not parameters:
            parameters.append(ParameterSpec(
                name="input_data",
                type_hint="Any",
                description="Input data"
            ))
        
        return parameters
    
    def _extract_return_type(self, prompt: str) -> str:
        """Extract return type from prompt."""
        # Look for explicit return type
        return_patterns = [
            r"returns?\s+(?:an?\s+)?(\w+)",
            r"output:\s*(\w+)",
            r"(?:should\s+)?(?:return|give|produce)\s+(?:an?\s+)?(\w+)",
        ]
        
        for pattern in return_patterns:
            match = re.search(pattern, prompt, re.IGNORECASE)
            if match:
                return self._normalize_type(match.group(1))
        
        # Infer from context
        if re.search(r'\b(?:sum|count|length|size|number)\b', prompt, re.IGNORECASE):
            return "int"
        elif re.search(r'\b(?:list|array)\b', prompt, re.IGNORECASE):
            return "List[int]"
        elif re.search(r'\b(?:true|false|boolean)\b', prompt, re.IGNORECASE):
            return "bool"
        elif re.search(r'\b(?:string|text)\b', prompt, re.IGNORECASE):
            return "str"
        
        return "Any"
    
    def _normalize_type(self, type_str: str) -> str:
        """Normalize type string to Python type hint."""
        type_str = type_str.lower().strip()
        return self.type_keywords.get(type_str, "Any")
    
    def _extract_constraints(self, prompt: str) -> List[str]:
        """Extract constraints from prompt."""
        constraints = []
        
        # Look for constraint patterns
        constraint_patterns = [
            r"(?:constraint|requirement|condition)s?:\s*([^\n]+)",
            r"(?:where|such that|given that)\s+([^\n]+)",
            r"(\d+\s*[<>=]+\s*\w+\s*[<>=]*\s*\d*)",
        ]
        
        for pattern in constraint_patterns:
            matches = re.finditer(pattern, prompt, re.IGNORECASE)
            for match in matches:
                constraint = match.group(1).strip()
                if constraint and len(constraint) > 3:
                    constraints.append(constraint)
        
        # Look for range constraints
        range_matches = re.finditer(
            r'(\w+)\s+(?:is\s+)?between\s+(\d+)\s+and\s+(\d+)',
            prompt,
            re.IGNORECASE
        )
        for match in range_matches:
            var, min_val, max_val = match.groups()
            constraints.append(f"{min_val} <= {var} <= {max_val}")
        
        return constraints
    
    def _extract_examples(self, prompt: str) -> List[Dict[str, Any]]:
        """Extract example inputs/outputs from prompt."""
        examples = []
        
        # Look for example patterns
        example_patterns = [
            r"(?:example|input|test case)s?:\s*([^\n]+)",
            r"(?:for|given)\s+([^,]+),\s+(?:output|return|result)s?\s+(?:is\s+)?([^\n]+)",
        ]
        
        for pattern in example_patterns:
            matches = re.finditer(pattern, prompt, re.IGNORECASE)
            for match in matches:
                try:
                    if len(match.groups()) == 2:
                        input_str, output_str = match.groups()
                        example = {
                            "input": self._parse_value(input_str),
                            "output": self._parse_value(output_str),
                            "description": f"Example: {input_str} -> {output_str}"
                        }
                        examples.append(example)
                except:
                    continue
        
        return examples
    
    def _extract_edge_cases(self, prompt: str) -> List[str]:
        """Extract edge cases from prompt."""
        edge_cases = []
        
        edge_keywords = [
            "edge case", "corner case", "boundary", "special case",
            "empty", "null", "zero", "negative", "large", "maximum", "minimum"
        ]
        
        for keyword in edge_keywords:
            if keyword in prompt.lower():
                # Extract context around keyword
                pattern = rf'([^.!?]*{re.escape(keyword)}[^.!?]*[.!?])'
                matches = re.finditer(pattern, prompt, re.IGNORECASE)
                for match in matches:
                    edge_cases.append(match.group(1).strip())
        
        # Add standard edge cases
        standard_edges = [
            "Empty input",
            "Single element",
            "Large input",
            "Boundary values"
        ]
        edge_cases.extend(standard_edges)
        
        return list(set(edge_cases))  # Remove duplicates
    
    def _parse_value(self, value_str: str) -> Any:
        """Parse string value into Python object."""
        value_str = value_str.strip()
        
        try:
            # Try JSON parsing first
            return json.loads(value_str)
        except:
            pass
        
        try:
            # Try eval for simple Python literals
            return eval(value_str, {"__builtins__": {}})
        except:
            pass
        
        # Return as string
        return value_str
