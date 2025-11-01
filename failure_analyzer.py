"""Failure Analyzer Module - Analyzes test failures and generates feedback."""
import re
from typing import List, Dict, Any
from sandbox_runner import TestResult

from logger import logger

class FailureAnalysis:
    """Container for failure analysis results."""
    
    def __init__(self):
        self.error_type = "unknown"
        self.failing_tests = []
        self.error_messages = []
        self.stack_traces = []
        self.suggested_fixes = []
        self.root_cause = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "error_type": self.error_type,
            "failing_tests": self.failing_tests,
            "error_messages": self.error_messages,
            "root_cause": self.root_cause,
            "suggested_fixes": self.suggested_fixes
        }
    
    def to_feedback(self) -> str:
        """Generate detailed feedback text for code refinement."""
        feedback_parts = []
        
        # Header with severity
        severity = "🔴 CRITICAL" if self.error_type in ["syntax", "import", "timeout"] else "⚠️ ERROR"
        feedback_parts.append(f"{severity} - {self.error_type.upper().replace('_', ' ')}")
        feedback_parts.append("=" * 80)
        
        # Root cause with emphasis
        feedback_parts.append(f"\n📋 ROOT CAUSE:")
        feedback_parts.append(f"   {self.root_cause}")
        
        # Failing tests with count
        if self.failing_tests:
            feedback_parts.append(f"\n❌ FAILING TESTS ({len(self.failing_tests)} test{'s' if len(self.failing_tests) > 1 else ''}):")
            for i, test in enumerate(self.failing_tests[:15], 1):  # Show up to 15 tests
                feedback_parts.append(f"   {i}. {test}")
            
            if len(self.failing_tests) > 15:
                feedback_parts.append(f"   ... and {len(self.failing_tests) - 15} more")
        
        # Error messages with better formatting - separate assertion errors
        if self.error_messages:
            assertion_errors = [msg for msg in self.error_messages if msg.startswith("❌")]
            other_errors = [msg for msg in self.error_messages if not msg.startswith("❌")]
            
            # Show assertion errors first (most common and important)
            if assertion_errors:
                feedback_parts.append(f"\n💥 ASSERTION FAILURES ({len(assertion_errors)}):")
                for i, msg in enumerate(assertion_errors[:15], 1):
                    feedback_parts.append(f"   {i}. {msg}")
                
                if len(assertion_errors) > 15:
                    feedback_parts.append(f"   ... and {len(assertion_errors) - 15} more")
            
            # Show other errors if any
            if other_errors:
                feedback_parts.append(f"\n💥 OTHER ERRORS ({len(other_errors)}):")
                for i, msg in enumerate(other_errors[:10], 1):
                    clean_msg = msg.strip()
                    if clean_msg:
                        feedback_parts.append(f"   {i}. {clean_msg}")
                
                if len(other_errors) > 10:
                    feedback_parts.append(f"   ... and {len(other_errors) - 10} more")
        
        # Stack traces if available
        if self.stack_traces:
            feedback_parts.append(f"\n📍 STACK TRACE:")
            for trace in self.stack_traces[:3]:  # Show top 3 traces
                feedback_parts.append(f"   {trace[:500]}")  # Limit trace length
        
        # Suggested fixes with priority
        if self.suggested_fixes:
            feedback_parts.append(f"\n✅ SUGGESTED FIXES (Priority Order):")
            for i, fix in enumerate(self.suggested_fixes, 1):
                feedback_parts.append(f"   {i}. {fix}")
        
        # Action items summary
        feedback_parts.append(f"\n" + "=" * 80)
        feedback_parts.append("🎯 ACTION REQUIRED:")
        feedback_parts.append("   1. Fix the root cause identified above")
        feedback_parts.append("   2. Apply suggested fixes in priority order")
        feedback_parts.append("   3. Ensure ALL edge cases are handled")
        feedback_parts.append("   4. Test the implementation meets specification exactly")
        
        return "\n".join(feedback_parts)

class FailureAnalyzer:
    """Analyzes test failures and generates actionable feedback."""
    
    def __init__(self):
        self.error_patterns = {
            "assertion": r"AssertionError",
            "type": r"TypeError",
            "value": r"ValueError",
            "attribute": r"AttributeError",
            "index": r"IndexError",
            "key": r"KeyError",
            "zero_division": r"ZeroDivisionError",
            "name": r"NameError",
            "syntax": r"SyntaxError",
            "import": r"ImportError|ModuleNotFoundError",
            "timeout": r"timeout|TIMEOUT",
        }
    
    def analyze(self, test_result: TestResult, code: str = None) -> FailureAnalysis:
        """Analyze test results and generate feedback.
        
        Args:
            test_result: Test execution results
            code: Source code (optional, for better analysis)
            
        Returns:
            FailureAnalysis object
        """
        logger.info("Analyzing test failures",
                   failed=test_result.failed,
                   errors=test_result.errors)
        
        # Log stderr for debugging syntax/import errors
        if test_result.stderr and (test_result.failed == 0 and test_result.passed == 0):
            logger.warning("Test collection error detected",
                          stderr_preview=test_result.stderr[:500])
        
        analysis = FailureAnalysis()
        
        # Classify error type
        analysis.error_type = self._classify_error(test_result)
        
        # Extract failing tests with detailed information
        analysis.failing_tests = []
        for f in test_result.failures:
            test_name = f.get("test", "unknown")
            message = f.get("message", "")
            
            # Try to extract expected vs actual from assertion errors
            if message and "assert" in message.lower():
                # Format: test_name: Expected X but got Y
                if "==" in message or "!=" in message or "Expected" in message:
                    analysis.failing_tests.append(f"{test_name} → {message[:150]}")
                else:
                    analysis.failing_tests.append(test_name)
            else:
                analysis.failing_tests.append(test_name)
        
        # Extract error messages with context
        analysis.error_messages = self._extract_error_messages(test_result)
        
        # Extract stack traces
        analysis.stack_traces = self._extract_stack_traces(test_result)
        
        # DEBUG: Log extracted information
        logger.debug("Failure details extracted",
                    failing_tests=len(analysis.failing_tests),
                    test_names=analysis.failing_tests[:5],
                    error_messages=len(analysis.error_messages),
                    error_preview=analysis.error_messages[:3] if analysis.error_messages else [],
                    stack_traces=len(analysis.stack_traces))
        
        # Determine root cause with enhanced analysis
        analysis.root_cause = self._determine_root_cause(
            test_result, 
            analysis.error_type,
            code
        )
        
        # Generate suggested fixes
        analysis.suggested_fixes = self._generate_suggestions(
            analysis.error_type,
            test_result,
            code
        )
        
        logger.info("Analysis completed",
                   error_type=analysis.error_type,
                   failing_count=len(analysis.failing_tests))
        
        return analysis
    
    def _classify_error(self, test_result: TestResult) -> str:
        """Classify the primary error type.
        
        Args:
            test_result: Test results
            
        Returns:
            Error classification string
        """
        output = test_result.stdout + test_result.stderr
        
        # Check for timeout FIRST
        if test_result.timed_out:
            return "timeout"
        
        # Check for "DID NOT RAISE" BEFORE checking AssertionError
        # This indicates missing validation/error handling
        if "DID NOT RAISE" in output:
            return "partial_failure"  # Will trigger specific error handling suggestions
        
        # Now check each error pattern
        for error_name, pattern in self.error_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                return error_name
        
        # Check if all tests failed
        if test_result.failed > 0 and test_result.passed == 0:
            return "logic_error"
        
        # Partial failure
        if test_result.failed > 0:
            return "partial_failure"
        
        return "unknown"
    
    def _extract_error_messages(self, test_result: TestResult) -> List[str]:
        """Extract and parse error messages with enhanced assertion error handling.
        
        Args:
            test_result: Test results
            
        Returns:
            List of formatted error messages
        """
        messages = []
        
        # From structured failures - parse assertion errors intelligently
        for failure in test_result.failures:
            msg = failure.get("message", "")
            if not msg:
                continue
            
            # Parse assertion errors to extract expected vs actual
            if "AssertionError" in msg or "assert" in msg.lower():
                parsed_msg = self._parse_assertion_error(msg)
                messages.append(parsed_msg)
            # Parse import errors
            elif "ImportError" in msg or "ModuleNotFoundError" in msg or "cannot import" in msg.lower():
                parsed_msg = self._parse_import_error(msg, test_result.stderr)
                messages.append(parsed_msg)
            else:
                # Clean up other messages
                msg = msg.split('\n')[0][:200]  # First line, limited length
                messages.append(msg)
        
        # From stderr - for syntax/import errors, include more context
        if test_result.stderr:
            stderr_lines = test_result.stderr.split('\n')
            
            # For syntax errors, include the actual error line
            if "SyntaxError" in test_result.stderr:
                for i, line in enumerate(stderr_lines):
                    if "SyntaxError" in line or "^" in line or "File" in line:
                        messages.append(line.strip()[:300])
            
            # For import errors, use enhanced parser
            elif "ImportError" in test_result.stderr or "ModuleNotFoundError" in test_result.stderr:
                import_error_msg = self._parse_import_error(test_result.stderr, test_result.stderr)
                if import_error_msg and import_error_msg not in messages:
                    messages.append(import_error_msg)
            
            # For other errors, collect error lines
            else:
                for line in stderr_lines:
                    if any(err in line for err in ["Error", "ERROR", "Exception"]):
                        messages.append(line.strip()[:200])
        
        # Check stdout for "DID NOT RAISE" errors - these indicate missing exception handling
        if test_result.stdout and "DID NOT RAISE" in test_result.stdout:
            stdout_lines = test_result.stdout.split('\n')
            for line in stdout_lines:
                if "DID NOT RAISE" in line or "Failed: DID NOT RAISE" in line:
                    # Extract which exception was expected
                    messages.append(f"MISSING VALIDATION: {line.strip()[:300]}")
        
        return messages[:10]  # Increased from 5 to 10 for better context
    
    def _parse_assertion_error(self, message: str) -> str:
        """Parse assertion error to extract expected vs actual values.
        
        Common patterns:
        - "AssertionError: Expected X but got Y"
        - "assert X == Y" where X is actual, Y is expected
        - "AssertionError: assert 5 == 10"
        - "AssertionError: [1, 2] != [1, 2, 3]"
        
        Args:
            message: Raw assertion error message
            
        Returns:
            Formatted, human-readable error message
        """
        msg = message.strip()
        
        # Pattern 1: "Expected X but got Y" or "Expected X, got Y"
        expected_got_pattern = r"[Ee]xpected\s+(.+?)(?:,|\s+but)\s+got\s+(.+?)(?:\n|$|\.)"
        match = re.search(expected_got_pattern, msg)
        if match:
            expected = match.group(1).strip()
            actual = match.group(2).strip()
            return f"❌ Expected: {expected} | Actual: {actual}"
        
        # Pattern 2: "assert X == Y" or "assert X != Y"
        assert_compare_pattern = r"assert\s+(.+?)\s*(==|!=|<|>|<=|>=|is|in)\s+(.+?)(?:\n|$)"
        match = re.search(assert_compare_pattern, msg)
        if match:
            left = match.group(1).strip()
            operator = match.group(2).strip()
            right = match.group(3).strip()
            
            # Try to determine which is expected vs actual
            # Usually: assert actual == expected
            if operator == "==":
                return f"❌ Assertion failed: {left} == {right} | Actual: {left} | Expected: {right}"
            elif operator == "!=":
                return f"❌ Assertion failed: {left} should NOT equal {right} (but it does)"
            else:
                return f"❌ Assertion failed: {left} {operator} {right}"
        
        # Pattern 3: "AssertionError: X != Y" 
        direct_compare_pattern = r"AssertionError:\s*(.+?)\s*(==|!=)\s*(.+?)(?:\n|$)"
        match = re.search(direct_compare_pattern, msg)
        if match:
            left = match.group(1).strip()
            operator = match.group(2).strip()
            right = match.group(3).strip()
            if operator == "!=":
                return f"❌ Values differ: {left} vs {right}"
            else:
                return f"❌ Comparison failed: {left} {operator} {right}"
        
        # Pattern 4: "assert X" (boolean assertion)
        assert_bool_pattern = r"assert\s+(.+?)(?:\n|$)"
        match = re.search(assert_bool_pattern, msg)
        if match:
            condition = match.group(1).strip()
            return f"❌ Assertion failed: {condition} evaluated to False"
        
        # Pattern 5: Look for actual values in parentheses or after colon
        # "AssertionError: (5) != (10)"
        paren_pattern = r"\(([^)]+)\)\s*([!=<>]+)\s*\(([^)]+)\)"
        match = re.search(paren_pattern, msg)
        if match:
            left = match.group(1).strip()
            operator = match.group(2).strip()
            right = match.group(3).strip()
            return f"❌ Comparison: ({left}) {operator} ({right})"
        
        # Pattern 6: Check for list/dict comparisons
        if "[" in msg and "]" in msg:
            # Try to extract lists
            list_pattern = r"\[([^\]]*)\]"
            lists = re.findall(list_pattern, msg)
            if len(lists) >= 2:
                return f"❌ List comparison failed: [{lists[0]}] vs [{lists[1]}]"
        
        # Pattern 7: "AssertionError: message with detailed info"
        if "AssertionError:" in msg:
            after_error = msg.split("AssertionError:", 1)[1].strip()
            # Take first line or up to 150 chars
            first_line = after_error.split('\n')[0][:150]
            return f"❌ {first_line}"
        
        # Fallback: return first 150 chars
        return f"❌ {msg[:150]}"
    
    def _parse_import_error(self, message: str, stderr: str = "") -> str:
        """Parse import error to provide specific, actionable feedback.
        
        Common import error patterns:
        1. "cannot import name 'X' from 'impl'" - Function name mismatch
        2. "ModuleNotFoundError: No module named 'X'" - Missing dependency
        3. "ImportError: cannot import name 'X'" - Name doesn't exist
        4. Test expects function but code defines class (or vice versa)
        
        Args:
            message: Raw import error message
            stderr: Full stderr output for additional context
            
        Returns:
            Formatted, actionable error message
        """
        msg = message.strip()
        full_context = (stderr or "") + "\n" + msg
        
        # Pattern 1: "cannot import name 'X' from 'Y'"
        cannot_import_pattern = r"cannot import name ['\"]([^'\"]+)['\"](?:\s+from\s+['\"]([^'\"]+)['\"])?"
        match = re.search(cannot_import_pattern, msg, re.IGNORECASE)
        if match:
            missing_name = match.group(1)
            module_name = match.group(2) if match.group(2) else "impl"
            
            # Check if this is impl.py (our generated code)
            if module_name in ["impl", "impl.py"]:
                # Try to detect what's actually defined in impl
                suggestions = []
                
                # Check stderr for hints about what exists
                if "class" in full_context.lower():
                    suggestions.append("Implementation defines a CLASS, but tests expect a FUNCTION")
                    suggestions.append(f"Either: Rename your class to '{missing_name}' OR create a function '{missing_name}' that uses the class")
                
                return (f"🔴 IMPORT ERROR: Cannot import '{missing_name}' from impl.py\n"
                       f"   ↳ The test file expects a function/class named '{missing_name}'\n"
                       f"   ↳ But impl.py does not define this name\n"
                       f"   ↳ SOLUTION: Ensure your code defines exactly: def {missing_name}(...) or class {missing_name}:\n"
                       + ("\n   ↳ " + "\n   ↳ ".join(suggestions) if suggestions else ""))
            else:
                # External module import issue
                return (f"🔴 IMPORT ERROR: Cannot import '{missing_name}' from '{module_name}'\n"
                       f"   ↳ Missing dependency or wrong module name\n"
                       f"   ↳ SOLUTION: Install package with: pip install {module_name}")
        
        # Pattern 2: "ModuleNotFoundError: No module named 'X'"
        module_not_found_pattern = r"ModuleNotFoundError:\s*No module named ['\"]([^'\"]+)['\"]"
        match = re.search(module_not_found_pattern, msg)
        if match:
            module_name = match.group(1)
            
            # Check if it's a common package with different pip name
            pip_names = {
                "cv2": "opencv-python",
                "PIL": "Pillow",
                "sklearn": "scikit-learn",
                "yaml": "pyyaml",
            }
            
            pip_name = pip_names.get(module_name, module_name)
            
            return (f"🔴 MODULE NOT FOUND: '{module_name}'\n"
                   f"   ↳ Required package is not installed\n"
                   f"   ↳ SOLUTION: pip install {pip_name}")
        
        # Pattern 3: "ImportError" without specific details
        if "ImportError" in msg:
            # Try to extract the import statement
            import_stmt_pattern = r"from\s+(\S+)\s+import\s+(\S+)"
            match = re.search(import_stmt_pattern, full_context)
            if match:
                module = match.group(1)
                name = match.group(2)
                return (f"🔴 IMPORT ERROR: Cannot import '{name}' from '{module}'\n"
                       f"   ↳ Check that '{name}' is defined in {module}.py\n"
                       f"   ↳ Verify spelling and function/class name matches exactly")
        
        # Pattern 4: Check for function/class name mismatch hints in stderr
        if "from impl import" in full_context.lower():
            # Extract what's being imported
            import_line = re.search(r"from impl import\s+(\w+)", full_context, re.IGNORECASE)
            if import_line:
                expected_name = import_line.group(1)
                return (f"🔴 IMPORT ERROR: Test file cannot import '{expected_name}' from impl.py\n"
                       f"   ↳ CRITICAL: Your function/class name MUST be exactly '{expected_name}'\n"
                       f"   ↳ Check for:\n"
                       f"      • Spelling mistakes\n"
                       f"      • Wrong capitalization\n"
                       f"      • Function defined but not at module level\n"
                       f"      • Class defined when function expected (or vice versa)\n"
                       f"   ↳ SOLUTION: Define exactly: def {expected_name}(...): or class {expected_name}:")
        
        # Pattern 5: Generic ImportError
        if "ImportError" in msg or "ModuleNotFoundError" in msg:
            return f"🔴 IMPORT ERROR: {msg[:200]}\n   ↳ Check module/function names match specification exactly"
        
        # Fallback
        return f"🔴 IMPORT ISSUE: {msg[:200]}"
    
    def _extract_stack_traces(self, test_result: TestResult) -> List[str]:
        """Extract stack traces from test output.
        
        Args:
            test_result: Test results
            
        Returns:
            List of stack traces
        """
        traces = []
        
        # Extract from structured failures
        for failure in test_result.failures:
            trace = failure.get("traceback", "")
            if trace:
                # Take the most relevant part of the trace
                trace_lines = trace.split('\n')
                # Find lines related to impl.py (our code)
                impl_lines = [line for line in trace_lines if 'impl.py' in line or 'line' in line.lower()]
                if impl_lines:
                    traces.append('\n'.join(impl_lines[:5]))
                elif len(trace_lines) > 0:
                    # Take last few lines (usually most relevant)
                    traces.append('\n'.join(trace_lines[-5:]))
        
        return traces[:3]  # Return top 3 traces
    
    def _determine_root_cause(self, test_result: TestResult, 
                             error_type: str,
                             code: str = None) -> str:
        """Determine root cause of failures with enhanced analysis.
        
        Args:
            test_result: Test results
            error_type: Classified error type
            code: Source code for deeper analysis
            
        Returns:
            Detailed root cause description
        """
        # Base causes
        causes = {
            "timeout": "Function runs too long or contains infinite loop",
            "assertion": "Function returns incorrect values - logic error in implementation",
            "type": "Type mismatch - function called with wrong type or returns wrong type",
            "value": "ValueError raised - function receives or produces invalid values",
            "attribute": "AttributeError - accessing non-existent attribute or method",
            "index": "IndexError - list/array index out of bounds",
            "key": "KeyError - dictionary key not found",
            "zero_division": "ZeroDivisionError - division by zero in calculation",
            "name": "NameError - variable or function not defined",
            "syntax": "SyntaxError - code has invalid Python syntax",
            "import": "ImportError - missing or incorrect imports, or function name mismatch",
            "logic_error": "Complete logic failure - all tests failed",
            "partial_failure": "Some edge cases not handled correctly - partial implementation",
        }
        
        base_cause = causes.get(error_type, "Unknown error in implementation")
        
        # Enhanced analysis based on code content
        if code:
            enhanced_details = []
            
            # Check for common patterns
            if error_type == "timeout" and "while True" in code:
                enhanced_details.append("Detected 'while True' loop - missing break condition")
            elif error_type == "timeout" and "recursion" in code.lower():
                enhanced_details.append("Recursive function may be missing base case")
            
            if error_type == "assertion":
                # Check for missing return
                if "return" not in code:
                    enhanced_details.append("Function may be missing return statement")
                # Check for partial returns
                elif code.count("return") == 1 and ("if" in code or "for" in code):
                    enhanced_details.append("Function may not return in all code paths")
            
            if error_type == "index" and "[" in code:
                enhanced_details.append("Check array bounds before accessing elements")
            
            if error_type == "import":
                # Analyze import-related issues more deeply with detailed context
                stderr_lower = test_result.stderr.lower()
                
                # Check if function/class name mismatch
                if "cannot import name" in stderr_lower:
                    # Try to extract expected name
                    import_match = re.search(r"cannot import name ['\"]([^'\"]+)['\"]", test_result.stderr, re.IGNORECASE)
                    if import_match:
                        expected_name = import_match.group(1)
                        enhanced_details.append(f"Test expects name '{expected_name}' but it's not defined")
                        
                        # Check what's actually in the code
                        if "def " in code and "class " not in code:
                            # Has function but wrong name
                            func_match = re.search(r"def\s+(\w+)\s*\(", code)
                            if func_match:
                                actual_name = func_match.group(1)
                                enhanced_details.append(f"Code defines '{actual_name}' but tests import '{expected_name}'")
                                enhanced_details.append(f"SOLUTION: Rename function from '{actual_name}' to '{expected_name}'")
                        elif "class " in code and "def " not in code:
                            # Has class when function expected
                            class_match = re.search(r"class\s+(\w+)", code)
                            if class_match:
                                class_name = class_match.group(1)
                                enhanced_details.append(f"Code defines class '{class_name}' but tests expect function '{expected_name}'")
                                enhanced_details.append(f"SOLUTION: Create function '{expected_name}' or rename class to '{expected_name}'")
                        elif "class " in code and "def " in code:
                            # Has both - might be helper class
                            enhanced_details.append("Code has both classes and functions - ensure the expected name is defined at module level")
                        else:
                            enhanced_details.append("No function or class definition found - code may be empty or malformed")
                
                # Check for module not found (missing dependencies)
                elif "no module named" in stderr_lower:
                    module_match = re.search(r"no module named ['\"]([^'\"]+)['\"]", test_result.stderr, re.IGNORECASE)
                    if module_match:
                        missing_module = module_match.group(1)
                        enhanced_details.append(f"Missing required module: {missing_module}")
                        enhanced_details.append(f"SOLUTION: Add 'import {missing_module}' or install with 'pip install {missing_module}'")
            
            if enhanced_details:
                return f"{base_cause}. {' '.join(enhanced_details)}"
        
        # Add context from test results
        if test_result.stderr:
            if "unexpected indent" in test_result.stderr:
                return f"{base_cause}. Detected unexpected indentation - likely missing class or function definition header"
            elif "cannot import name" in test_result.stderr:
                # Extract the expected name for more specific message
                import_match = re.search(r"cannot import name ['\"]([^'\"]+)['\"]", test_result.stderr, re.IGNORECASE)
                if import_match:
                    expected_name = import_match.group(1)
                    return f"{base_cause}. Test file expects '{expected_name}' but impl.py does not define it - check spelling and ensure name matches exactly"
                return f"{base_cause}. Test file cannot import the function - check function name matches specification exactly"
        
        return base_cause
    
    def _generate_suggestions(self, error_type: str, 
                            test_result: TestResult,
                            code: str = None) -> List[str]:
        """Generate suggested fixes based on error type.
        
        Args:
            error_type: Classified error type
            test_result: Test results
            code: Source code
            
        Returns:
            List of suggested fixes
        """
        suggestions = []
        
        if error_type == "timeout":
            suggestions.extend([
                "Add base case to recursive functions",
                "Replace infinite loops with bounded iterations",
                "Optimize algorithm complexity",
                "Check for infinite recursion"
            ])
        
        elif error_type == "assertion":
            suggestions.extend([
                "Review function logic and return values",
                "Check calculations and formulas",
                "Verify edge case handling",
                "Test with example inputs manually"
            ])
        
        elif error_type == "type":
            suggestions.extend([
                "Add type validation for inputs",
                "Ensure return type matches specification",
                "Check type conversions (int, str, list, etc.)",
                "Add type hints to function signature"
            ])
        
        elif error_type == "index":
            suggestions.extend([
                "Add bounds checking before list access",
                "Verify list is not empty before indexing",
                "Use list.get() for safe access",
                "Check loop ranges and indices"
            ])
        
        elif error_type == "key":
            suggestions.extend([
                "Use dict.get() with default value",
                "Check if key exists before access",
                "Verify dictionary structure",
                "Handle missing keys gracefully"
            ])
        
        elif error_type == "zero_division":
            suggestions.extend([
                "Add check for zero before division",
                "Handle edge case where divisor is zero",
                "Return special value for undefined division"
            ])
        
        elif error_type == "name":
            suggestions.extend([
                "Define all variables before use",
                "Check variable names for typos",
                "Import required modules",
                "Verify function and variable scope"
            ])
        
        elif error_type == "syntax":
            suggestions.extend([
                "Fix syntax errors (colons, parentheses, indentation)",
                "Check for unclosed brackets or quotes",
                "Verify proper indentation",
                "Ensure valid Python syntax"
            ])
        
        elif error_type == "import":
            # Enhanced import error suggestions with specific context
            stderr_text = test_result.stderr if test_result.stderr else ""
            
            # Try to extract expected function/class name
            expected_name = None
            import_match = re.search(r"cannot import name ['\"]([^'\"]+)['\"]", stderr_text, re.IGNORECASE)
            if import_match:
                expected_name = import_match.group(1)
            
            if expected_name:
                suggestions.extend([
                    f"🔴 CRITICAL: Define exactly 'def {expected_name}(...)' or 'class {expected_name}:' in your code",
                    f"Check spelling and capitalization - name must be EXACTLY '{expected_name}'",
                    "Ensure the function/class is defined at MODULE LEVEL (not inside another function/class)",
                    "Verify no indentation errors that would hide the definition"
                ])
            else:
                suggestions.extend([
                    "Ensure the function name matches exactly what's imported in tests",
                    "Check the function is defined at module level in impl.py",
                    "Verify no typos in function name (case-sensitive)",
                    "Make sure the function name matches the specification"
                ])
            
            # Check for class vs function confusion
            if code and "class " in code:
                if "def " not in code or code.index("class ") < code.index("def "):
                    suggestions.append("⚠️ You defined a CLASS but tests might expect a FUNCTION - check requirements")
                    if expected_name:
                        suggestions.append(f"If tests need a function, add: def {expected_name}(...) that uses your class")
            
            # Check for missing imports
            if "no module named" in stderr_text.lower():
                module_match = re.search(r"no module named ['\"]([^'\"]+)['\"]", stderr_text, re.IGNORECASE)
                if module_match:
                    missing_module = module_match.group(1)
                    suggestions.insert(0, f"🔴 INSTALL MISSING MODULE: pip install {missing_module}")
                    suggestions.insert(1, f"Then add at top of code: import {missing_module}")
        
        elif error_type == "partial_failure":
            # Analyze which tests pass/fail
            if test_result.failures:
                failing_names = [f.get("test", "") for f in test_result.failures]
                
                # Check for "raises_error" or "raises" in test names - indicates missing error handling
                if any("raises" in name.lower() for name in failing_names):
                    suggestions.append("Add input validation and raise appropriate exceptions (ValueError, TypeError)")
                    suggestions.append("Check for empty inputs, invalid types, and boundary conditions")
                
                if any("empty" in name.lower() for name in failing_names):
                    suggestions.append("Handle empty input case")
                if any("zero" in name.lower() for name in failing_names):
                    suggestions.append("Handle zero value case")
                if any("negative" in name.lower() for name in failing_names):
                    suggestions.append("Handle negative numbers")
                if any("single" in name.lower() for name in failing_names):
                    suggestions.append("Handle single element case")
                if any("large" in name.lower() for name in failing_names):
                    suggestions.append("Handle large input values")
        
        # Additional check: if "DID NOT RAISE" appears in output, add specific suggestion
        if test_result.stdout and "DID NOT RAISE" in test_result.stdout:
            if not any("validation" in s.lower() for s in suggestions):
                suggestions.insert(0, "CRITICAL: Add input validation - tests expect exceptions to be raised for invalid inputs")
                suggestions.insert(1, "Use isinstance() to check types and raise TypeError for invalid types")
                suggestions.insert(2, "Check input constraints (length, values) and raise ValueError when violated")
        
        if not suggestions:
            suggestions.append("Review implementation against specification")
            suggestions.append("Test with failing test inputs manually")
        
        return suggestions
