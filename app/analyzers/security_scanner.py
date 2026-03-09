"""
Security scanner for Python code.
Detects OWASP Top 10 issues, hardcoded secrets, unsafe patterns,
and vulnerable dependency usage via AST + regex pattern matching.
"""
import ast
import re
import subprocess
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SecurityIssue:
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    category: str
    message: str
    lineno: int
    col: int = 0
    cwe: Optional[str] = None
    fix_hint: Optional[str] = None


@dataclass
class SecurityReport:
    path: str
    issues: list[SecurityIssue] = field(default_factory=list)

    @property
    def critical(self): return [i for i in self.issues if i.severity == "CRITICAL"]
    @property
    def high(self): return [i for i in self.issues if i.severity == "HIGH"]
    @property
    def medium(self): return [i for i in self.issues if i.severity == "MEDIUM"]
    @property
    def low(self): return [i for i in self.issues if i.severity == "LOW"]
    @property
    def score(self) -> int:
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 5, "LOW": 1}
        total = sum(weights.get(i.severity, 0) for i in self.issues)
        return max(0, 100 - total)


# ── Regex patterns for secret detection ─────────────────────────────────────

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',  "Hardcoded password", "CWE-259"),
    (r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key", "CWE-798"),
    (r'(?i)(secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret", "CWE-798"),
    (r'(?i)(token|auth_token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded token", "CWE-798"),
    (r'(?i)(aws_access_key_id)\s*=\s*["\'][A-Z0-9]{16,}["\']', "Hardcoded AWS key", "CWE-798"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Hardcoded private key", "CWE-321"),
    (r'(?i)(database_url|db_url)\s*=\s*["\']postgres[^"\']+["\']', "Hardcoded DB URL with credentials", "CWE-259"),
]


class SecurityScanner:
    """Scans Python source for security vulnerabilities."""

    def scan_file(self, file_path: str) -> SecurityReport:
        path = Path(file_path)
        if not path.exists():
            return SecurityReport(path=file_path)

        source = path.read_text(encoding="utf-8", errors="replace")
        return self.scan_source(source, str(path))

    def scan_source(self, source: str, path: str = "<string>") -> SecurityReport:
        report = SecurityReport(path=path)
        lines = source.splitlines()

        try:
            tree = ast.parse(source)
            self._scan_ast(tree, report)
        except SyntaxError:
            pass

        self._scan_secrets(lines, report)
        self._scan_dangerous_functions(lines, report)

        return report

    def _scan_ast(self, tree: ast.AST, report: SecurityReport):
        for node in ast.walk(tree):

            # SQL injection — string formatting in execute()
            if isinstance(node, ast.Call):
                func = node.func
                func_name = ""
                if isinstance(func, ast.Attribute):
                    func_name = func.attr
                elif isinstance(func, ast.Name):
                    func_name = func.id

                if func_name == "execute" and node.args:
                    arg = node.args[0]
                    if isinstance(arg, (ast.JoinedStr, ast.BinOp, ast.Mod)):
                        report.issues.append(SecurityIssue(
                            severity="CRITICAL",
                            category="SQL Injection",
                            message="Possible SQL injection: string formatting used in execute(). Use parameterized queries.",
                            lineno=node.lineno,
                            cwe="CWE-89",
                            fix_hint="Replace with cursor.execute(query, (param,)) using parameterized queries.",
                        ))

                # Unsafe deserialization
                if func_name in ("loads", "load") and isinstance(func, ast.Attribute):
                    if isinstance(func.value, ast.Name) and func.value.id == "pickle":
                        report.issues.append(SecurityIssue(
                            severity="CRITICAL",
                            category="Insecure Deserialization",
                            message="pickle.loads() on untrusted data allows arbitrary code execution.",
                            lineno=node.lineno,
                            cwe="CWE-502",
                            fix_hint="Use json.loads() for data interchange, or validate pickle source is trusted.",
                        ))

                # Shell injection
                if func_name in ("system", "popen") and isinstance(func, ast.Attribute):
                    report.issues.append(SecurityIssue(
                        severity="HIGH",
                        category="Command Injection",
                        message=f"os.{func_name}() can lead to shell injection. Use subprocess with shell=False.",
                        lineno=node.lineno,
                        cwe="CWE-78",
                        fix_hint="Use subprocess.run([...], shell=False) with a list of arguments.",
                    ))

                # subprocess with shell=True
                if func_name in ("run", "call", "Popen", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            report.issues.append(SecurityIssue(
                                severity="HIGH",
                                category="Command Injection",
                                message="subprocess called with shell=True — vulnerable to shell injection.",
                                lineno=node.lineno,
                                cwe="CWE-78",
                                fix_hint="Use shell=False and pass arguments as a list.",
                            ))

                # Use of eval()
                if isinstance(func, ast.Name) and func.id == "eval":
                    report.issues.append(SecurityIssue(
                        severity="CRITICAL",
                        category="Code Injection",
                        message="eval() executes arbitrary code. Never use on untrusted input.",
                        lineno=node.lineno,
                        cwe="CWE-95",
                        fix_hint="Replace eval() with ast.literal_eval() for safe expression evaluation.",
                    ))

                # Use of exec()
                if isinstance(func, ast.Name) and func.id == "exec":
                    report.issues.append(SecurityIssue(
                        severity="CRITICAL",
                        category="Code Injection",
                        message="exec() executes arbitrary code strings. Avoid in production.",
                        lineno=node.lineno,
                        cwe="CWE-95",
                        fix_hint="Refactor to avoid dynamic code execution.",
                    ))

                # assert used for security checks
                if isinstance(node, ast.Assert):
                    pass  # handled below

            # Assert used as security gate
            if isinstance(node, ast.Assert):
                report.issues.append(SecurityIssue(
                    severity="MEDIUM",
                    category="Improper Access Control",
                    message=f"assert statement at line {node.lineno} is stripped in optimized mode (-O). Don't use for security checks.",
                    lineno=node.lineno,
                    cwe="CWE-617",
                    fix_hint="Replace assert with explicit if/raise checks.",
                ))

            # Weak hash algorithms
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in ("md5", "sha1"):
                    if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                        report.issues.append(SecurityIssue(
                            severity="MEDIUM",
                            category="Weak Cryptography",
                            message=f"hashlib.{func.attr}() is cryptographically weak. Use SHA-256 or better.",
                            lineno=node.lineno,
                            cwe="CWE-327",
                            fix_hint="Use hashlib.sha256() or hashlib.sha3_256() instead.",
                        ))

                # HTTP requests without SSL verification
                if isinstance(func, ast.Attribute) and func.attr in ("get", "post", "put", "delete", "request"):
                    for kw in node.keywords:
                        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            report.issues.append(SecurityIssue(
                                severity="HIGH",
                                category="Insecure Transport",
                                message="SSL verification disabled (verify=False). Vulnerable to MITM attacks.",
                                lineno=node.lineno,
                                cwe="CWE-295",
                                fix_hint="Remove verify=False or use a proper CA bundle.",
                            ))

    def _scan_secrets(self, lines: list[str], report: SecurityReport):
        for lineno, line in enumerate(lines, start=1):
            for pattern, label, cwe in SECRET_PATTERNS:
                if re.search(pattern, line):
                    report.issues.append(SecurityIssue(
                        severity="CRITICAL",
                        category="Secrets Exposure",
                        message=f"{label} detected. Never hardcode credentials in source code.",
                        lineno=lineno,
                        cwe=cwe,
                        fix_hint="Move to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
                    ))

    def _scan_dangerous_functions(self, lines: list[str], report: SecurityReport):
        dangerous = {
            "marshal.loads": ("CRITICAL", "Insecure Deserialization", "CWE-502",
                              "marshal.loads on untrusted data. Use JSON instead."),
            "yaml.load(": ("HIGH", "Insecure Deserialization", "CWE-502",
                           "yaml.load() without Loader allows code execution. Use yaml.safe_load()."),
            "random.random": ("LOW", "Weak Randomness", "CWE-330",
                              "random module is not cryptographically secure. Use secrets module."),
            "random.randint": ("LOW", "Weak Randomness", "CWE-330",
                               "random module is not cryptographically secure. Use secrets.randbelow()."),
            "tempfile.mktemp": ("MEDIUM", "Insecure Temp File", "CWE-377",
                                "mktemp() has a race condition. Use mkstemp() or NamedTemporaryFile()."),
        }
        for lineno, line in enumerate(lines, start=1):
            for pattern, (severity, category, cwe, msg) in dangerous.items():
                if pattern in line:
                    report.issues.append(SecurityIssue(
                        severity=severity,
                        category=category,
                        message=msg,
                        lineno=lineno,
                        cwe=cwe,
                    ))
