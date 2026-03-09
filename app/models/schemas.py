"""Pydantic schemas for PyGuard AI API."""
from pydantic import BaseModel
from typing import Optional


class SecurityIssueSchema(BaseModel):
    severity: str
    category: str
    message: str
    lineno: int
    cwe: Optional[str] = None
    fix_hint: Optional[str] = None


class FunctionMetricsSchema(BaseModel):
    name: str
    lineno: int
    complexity: int
    loc: int
    args_count: int
    max_nesting: int
    has_docstring: bool
    issues: list[str]


class AIFixSchema(BaseModel):
    issue_summary: str
    explanation: str
    fixed_code: Optional[str] = None
    references: list[str]


class ReviewResponse(BaseModel):
    filename: str
    security_score: int
    quality_score: int
    overall_summary: str
    total_loc: int
    functions_analyzed: int
    security_issues: list[SecurityIssueSchema]
    function_issues: list[FunctionMetricsSchema]
    file_issues: list[str]
    ai_fixes: list[AIFixSchema]
    ai_available: bool


class HealthResponse(BaseModel):
    status: str
    version: str
    ai_enabled: bool
