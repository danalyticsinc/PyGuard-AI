"""
FastAPI router for code review endpoints.
"""
import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse

from app.analyzers.ast_analyzer import ASTAnalyzer
from app.analyzers.security_scanner import SecurityScanner
from app.models.schemas import ReviewResponse, SecurityIssueSchema, FunctionMetricsSchema, AIFixSchema

router = APIRouter()
ast_analyzer = ASTAnalyzer()
security_scanner = SecurityScanner()


def _run_review(source: str, filename: str, use_ai: bool) -> ReviewResponse:
    metrics = ast_analyzer.analyze_source(source, filename)
    security = security_scanner.scan_source(source, filename)

    ai_fixes = []
    ai_available = False

    if use_ai and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            from app.services.ai_engine import AIEngine
            engine = AIEngine()
            result = engine.review(source, metrics, security, filename)
            ai_fixes = [
                AIFixSchema(
                    issue_summary=f.issue_summary,
                    explanation=f.explanation,
                    fixed_code=f.fixed_code,
                    references=f.references,
                )
                for f in result.priority_fixes
            ]
            ai_available = True
        except Exception:
            ai_available = False

    return ReviewResponse(
        filename=filename,
        security_score=security.score,
        quality_score=_compute_quality_score(metrics),
        overall_summary=_build_summary(metrics, security),
        total_loc=metrics.total_loc,
        functions_analyzed=len(metrics.functions),
        security_issues=[
            SecurityIssueSchema(
                severity=i.severity,
                category=i.category,
                message=i.message,
                lineno=i.lineno,
                cwe=i.cwe,
                fix_hint=i.fix_hint,
            )
            for i in security.issues
        ],
        function_issues=[
            FunctionMetricsSchema(
                name=f.name,
                lineno=f.lineno,
                complexity=f.complexity,
                loc=f.loc,
                args_count=f.args_count,
                max_nesting=f.max_nesting,
                has_docstring=f.has_docstring,
                issues=f.issues,
            )
            for f in metrics.functions if f.issues
        ],
        file_issues=metrics.issues,
        ai_fixes=ai_fixes,
        ai_available=ai_available,
    )


def _compute_quality_score(metrics) -> int:
    deductions = 0
    for fn in metrics.functions:
        deductions += len(fn.issues) * 5
    deductions += len(metrics.issues) * 3
    return max(0, 100 - deductions)


def _build_summary(metrics, security) -> str:
    total_issues = len(security.issues)
    critical = len(security.critical)
    high = len(security.high)
    fn_issues = sum(len(f.issues) for f in metrics.functions)
    parts = []
    if critical:
        parts.append(f"{critical} critical security issue(s) require immediate attention")
    if high:
        parts.append(f"{high} high severity issue(s) detected")
    if fn_issues:
        parts.append(f"{fn_issues} code quality issue(s) across {len(metrics.functions)} function(s)")
    if not parts:
        parts.append("No major issues detected")
    return ". ".join(parts) + "."


@router.post("/review/upload", response_model=ReviewResponse)
async def review_uploaded_file(
    file: UploadFile = File(...),
    ai: bool = Query(default=True, description="Enable Claude AI suggestions"),
):
    """Upload a Python file for security and quality review."""
    if not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files are supported.")

    content = await file.read()
    if len(content) > 500_000:
        raise HTTPException(status_code=413, detail="File too large. Max 500KB.")

    source = content.decode("utf-8", errors="replace")
    return _run_review(source, file.filename, use_ai=ai)


@router.post("/review/snippet", response_model=ReviewResponse)
async def review_code_snippet(
    payload: dict,
    ai: bool = Query(default=True),
):
    """Review a raw Python code snippet (JSON body: {code, filename})."""
    source = payload.get("code", "")
    filename = payload.get("filename", "snippet.py")
    if not source.strip():
        raise HTTPException(status_code=400, detail="No code provided.")
    return _run_review(source, filename, use_ai=ai)


@router.get("/review/demo", response_model=ReviewResponse)
async def review_demo(ai: bool = Query(default=False)):
    """Run a demo review on a deliberately vulnerable Python snippet."""
    demo_code = '''
import os
import pickle
import hashlib
import sqlite3

PASSWORD = "admin123"
API_KEY = "sk-abcdefghijklmnop"

def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def run_command(cmd):
    os.system(cmd)

def load_data(data):
    return pickle.loads(data)

def process(x, y, z, a, b, c, d):
    if x > 0:
        if y > 0:
            if z > 0:
                if a > 0:
                    if b > 0:
                        return x + y + z + a + b + c + d
    return 0
'''
    return _run_review(demo_code, "vulnerable_demo.py", use_ai=ai)
