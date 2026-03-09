"""
Claude AI-powered fix suggestion engine.
Takes security issues and code quality problems and generates
actionable fix suggestions with corrected code snippets.
"""
import os
import anthropic
from dataclasses import dataclass
from typing import Optional

from app.analyzers.ast_analyzer import FileMetrics, FunctionMetrics
from app.analyzers.security_scanner import SecurityReport, SecurityIssue


@dataclass
class AIFixSuggestion:
    issue_summary: str
    explanation: str
    fixed_code: Optional[str]
    references: list[str]


@dataclass
class AIReviewResult:
    overall_summary: str
    security_score: int
    quality_score: int
    priority_fixes: list[AIFixSuggestion]
    raw_response: str


class AIEngine:
    """Uses Claude AI to generate intelligent code fix suggestions."""

    MODEL = "claude-opus-4-6"

    def __init__(self):
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set.")
        self.client = anthropic.Anthropic(api_key=api_key)

    def review(
        self,
        source_code: str,
        file_metrics: FileMetrics,
        security_report: SecurityReport,
        filename: str = "code.py",
    ) -> AIReviewResult:
        prompt = self._build_prompt(source_code, file_metrics, security_report, filename)

        message = self.client.messages.create(
            model=self.MODEL,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
            system=self._system_prompt(),
        )

        raw = message.content[0].text
        return self._parse_response(raw, security_report)

    def _system_prompt(self) -> str:
        return """You are PyGuard AI — an enterprise-grade Python code security and quality review agent.

Your job is to:
1. Analyze Python code for security vulnerabilities, bugs, and quality issues
2. Provide clear, actionable fix suggestions with corrected code
3. Prioritize issues by severity (CRITICAL > HIGH > MEDIUM > LOW)
4. Reference CWE IDs and Python best practices
5. Be concise and developer-friendly — no fluff

Output format must be structured JSON:
{
  "overall_summary": "2-3 sentence summary of the code quality and security posture",
  "security_score": <0-100>,
  "quality_score": <0-100>,
  "priority_fixes": [
    {
      "issue_summary": "short title",
      "explanation": "why this is a problem",
      "fixed_code": "corrected Python code snippet or null",
      "references": ["CWE-XXX", "OWASP link", etc]
    }
  ]
}

Be ruthlessly honest. If the code is bad, say so clearly."""

    def _build_prompt(
        self,
        source: str,
        metrics: FileMetrics,
        security: SecurityReport,
        filename: str,
    ) -> str:
        issues_text = ""
        if security.issues:
            issues_text = "\n\nSECURITY ISSUES DETECTED:\n"
            for i in security.issues:
                issues_text += f"- [{i.severity}] Line {i.lineno}: {i.message}"
                if i.cwe:
                    issues_text += f" ({i.cwe})"
                issues_text += "\n"

        quality_text = ""
        if metrics.issues:
            quality_text = "\nFILE QUALITY ISSUES:\n"
            for issue in metrics.issues:
                quality_text += f"- {issue}\n"

        func_text = ""
        problematic_funcs = [f for f in metrics.functions if f.issues]
        if problematic_funcs:
            func_text = "\nFUNCTION ISSUES:\n"
            for fn in problematic_funcs[:5]:
                func_text += f"- {fn.name}() (line {fn.lineno}): {', '.join(fn.issues)}\n"

        return f"""Review this Python file: {filename}

FILE STATS:
- Lines of code: {metrics.total_loc}
- Functions: {len(metrics.functions)}
- Classes: {len(metrics.classes)}
- Security score (static analysis): {security.score}/100
{issues_text}{quality_text}{func_text}

SOURCE CODE:
```python
{source[:6000]}
```

Provide a comprehensive security and quality review with prioritized fixes as JSON."""

    def _parse_response(self, raw: str, security_report: SecurityReport) -> AIReviewResult:
        import json, re

        json_match = re.search(r'\{[\s\S]*\}', raw)
        if json_match:
            try:
                data = json.loads(json_match.group())
                fixes = []
                for item in data.get("priority_fixes", []):
                    fixes.append(AIFixSuggestion(
                        issue_summary=item.get("issue_summary", ""),
                        explanation=item.get("explanation", ""),
                        fixed_code=item.get("fixed_code"),
                        references=item.get("references", []),
                    ))
                return AIReviewResult(
                    overall_summary=data.get("overall_summary", ""),
                    security_score=data.get("security_score", security_report.score),
                    quality_score=data.get("quality_score", 70),
                    priority_fixes=fixes,
                    raw_response=raw,
                )
            except json.JSONDecodeError:
                pass

        return AIReviewResult(
            overall_summary=raw[:500],
            security_score=security_report.score,
            quality_score=70,
            priority_fixes=[],
            raw_response=raw,
        )

    def generate_fix(self, source: str, issue: SecurityIssue) -> str:
        """Generate a targeted fix for a single security issue."""
        message = self.client.messages.create(
            model=self.MODEL,
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": f"""Fix this specific security issue in the Python code:

Issue: [{issue.severity}] {issue.message}
Line: {issue.lineno}
CWE: {issue.cwe or 'N/A'}
Fix hint: {issue.fix_hint or 'N/A'}

Source code:
```python
{source}
```

Return ONLY the corrected Python code with a brief comment explaining the fix. No explanation needed outside the code."""
            }],
        )
        return message.content[0].text
