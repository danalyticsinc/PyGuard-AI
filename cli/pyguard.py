"""
PyGuard AI CLI — pyguard
Enterprise Python code security and quality auditor.

Usage:
    pyguard scan path/to/file.py
    pyguard scan path/to/project/ --recursive
    pyguard scan file.py --no-ai --output report.json
"""
import os
import sys
import json
import glob
from pathlib import Path

import click

from app.analyzers.ast_analyzer import ASTAnalyzer
from app.analyzers.security_scanner import SecurityScanner

ast_analyzer = ASTAnalyzer()
security_scanner = SecurityScanner()

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "cyan",
    "LOW": "white",
}

SEVERITY_ICONS = {
    "CRITICAL": "✖",
    "HIGH": "⚠",
    "MEDIUM": "●",
    "LOW": "○",
}


def _print_banner():
    click.echo(click.style("""
╔═══════════════════════════════════════╗
║         PyGuard AI  v1.0.0            ║
║  Python Security & Quality Auditor    ║
╚═══════════════════════════════════════╝
""", fg="blue", bold=True))


def _print_score(label: str, score: int):
    if score >= 80:
        color = "green"
        grade = "A"
    elif score >= 60:
        color = "yellow"
        grade = "B"
    elif score >= 40:
        color = "red"
        grade = "C"
    else:
        color = "red"
        grade = "F"
    click.echo(f"  {label}: " + click.style(f"{score}/100 ({grade})", fg=color, bold=True))


def _scan_file(file_path: str, use_ai: bool, verbose: bool) -> dict:
    path = Path(file_path)
    source = path.read_text(encoding="utf-8", errors="replace")

    metrics = ast_analyzer.analyze_source(source, str(path))
    security = security_scanner.scan_source(source, str(path))

    quality_score = max(0, 100 - (
        sum(len(f.issues) for f in metrics.functions) * 5 +
        len(metrics.issues) * 3
    ))

    click.echo(f"\n{'─'*50}")
    click.echo(click.style(f"  {path.name}", bold=True))
    click.echo(f"{'─'*50}")
    click.echo(f"  Lines: {metrics.total_loc}  |  Functions: {len(metrics.functions)}  |  Classes: {len(metrics.classes)}")
    _print_score("Security Score", security.score)
    _print_score("Quality Score ", quality_score)

    # Security issues
    if security.issues:
        click.echo(click.style(f"\n  Security Issues ({len(security.issues)}):", bold=True))
        for issue in security.issues:
            color = SEVERITY_COLORS.get(issue.severity, "white")
            icon = SEVERITY_ICONS.get(issue.severity, "●")
            prefix = click.style(f"  {icon} [{issue.severity}]", fg=color, bold=True)
            click.echo(f"{prefix} Line {issue.lineno}: {issue.message}")
            if verbose and issue.fix_hint:
                click.echo(click.style(f"     → Fix: {issue.fix_hint}", fg="green"))
            if verbose and issue.cwe:
                click.echo(click.style(f"     → {issue.cwe}", fg="bright_black"))
    else:
        click.echo(click.style("\n  ✓ No security issues detected.", fg="green"))

    # Quality issues
    quality_issues = []
    for fn in metrics.functions:
        for issue in fn.issues:
            quality_issues.append(f"{fn.name}(): {issue}")
    quality_issues.extend(metrics.issues)

    if quality_issues:
        click.echo(click.style(f"\n  Code Quality Issues ({len(quality_issues)}):", bold=True))
        for issue in quality_issues[:10]:
            click.echo(f"  {click.style('●', fg='cyan')} {issue}")
    else:
        click.echo(click.style("  ✓ No quality issues detected.", fg="green"))

    # AI suggestions
    ai_fixes = []
    if use_ai and os.environ.get("ANTHROPIC_API_KEY"):
        click.echo(click.style("\n  Generating AI fix suggestions...", fg="blue"))
        try:
            from app.services.ai_engine import AIEngine
            engine = AIEngine()
            result = engine.review(source, metrics, security, path.name)
            click.echo(click.style(f"\n  AI Summary: ", bold=True) + result.overall_summary)
            if result.priority_fixes:
                click.echo(click.style(f"\n  Priority Fixes ({len(result.priority_fixes)}):", bold=True))
                for i, fix in enumerate(result.priority_fixes[:3], 1):
                    click.echo(f"\n  {i}. {click.style(fix.issue_summary, bold=True, fg='yellow')}")
                    click.echo(f"     {fix.explanation}")
                    if fix.fixed_code and verbose:
                        click.echo(click.style("     Fixed code:", fg="green"))
                        for line in fix.fixed_code.strip().splitlines()[:10]:
                            click.echo(f"       {line}")
            ai_fixes = [
                {"issue": f.issue_summary, "explanation": f.explanation, "fixed_code": f.fixed_code}
                for f in result.priority_fixes
            ]
        except Exception as e:
            click.echo(click.style(f"  AI unavailable: {e}", fg="yellow"))
    elif use_ai:
        click.echo(click.style("\n  ⚠ Set ANTHROPIC_API_KEY for AI-powered suggestions.", fg="yellow"))

    return {
        "file": str(path),
        "security_score": security.score,
        "quality_score": quality_score,
        "security_issues": [
            {"severity": i.severity, "category": i.category, "message": i.message,
             "lineno": i.lineno, "cwe": i.cwe}
            for i in security.issues
        ],
        "quality_issues": quality_issues,
        "ai_fixes": ai_fixes,
    }


@click.group()
def cli():
    """PyGuard AI — Enterprise Python Security & Quality Auditor"""
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Scan all .py files recursively")
@click.option("--no-ai", is_flag=True, help="Disable Claude AI suggestions")
@click.option("--output", "-o", type=click.Path(), help="Save JSON report to file")
@click.option("--verbose", "-v", is_flag=True, help="Show fix hints and code snippets")
@click.option("--min-severity", default="LOW", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              help="Minimum severity to report")
def scan(target, recursive, no_ai, output, verbose, min_severity):
    """Scan a Python file or directory for security and quality issues."""
    _print_banner()

    use_ai = not no_ai
    target_path = Path(target)

    if target_path.is_dir():
        if recursive:
            files = list(target_path.rglob("*.py"))
        else:
            files = list(target_path.glob("*.py"))
        if not files:
            click.echo(click.style("No Python files found.", fg="yellow"))
            return
        click.echo(f"  Scanning {len(files)} Python file(s) in {target_path}...\n")
    else:
        files = [target_path]

    results = []
    total_critical = 0
    total_high = 0

    for f in files:
        try:
            result = _scan_file(str(f), use_ai=use_ai, verbose=verbose)
            results.append(result)
            total_critical += sum(1 for i in result["security_issues"] if i["severity"] == "CRITICAL")
            total_high += sum(1 for i in result["security_issues"] if i["severity"] == "HIGH")
        except Exception as e:
            click.echo(click.style(f"\n  Error scanning {f}: {e}", fg="red"))

    # Summary
    click.echo(f"\n{'═'*50}")
    click.echo(click.style("  SCAN COMPLETE", bold=True))
    click.echo(f"{'═'*50}")
    click.echo(f"  Files scanned: {len(results)}")
    if total_critical:
        click.echo(click.style(f"  Critical issues: {total_critical} — FIX IMMEDIATELY", fg="red", bold=True))
    if total_high:
        click.echo(click.style(f"  High issues:     {total_high}", fg="yellow", bold=True))

    avg_security = sum(r["security_score"] for r in results) / len(results) if results else 0
    avg_quality = sum(r["quality_score"] for r in results) / len(results) if results else 0
    click.echo(f"\n  Average Security Score: {avg_security:.0f}/100")
    click.echo(f"  Average Quality Score:  {avg_quality:.0f}/100\n")

    if output:
        report = {"files": results, "summary": {
            "files_scanned": len(results),
            "total_critical": total_critical,
            "total_high": total_high,
            "avg_security_score": round(avg_security, 1),
            "avg_quality_score": round(avg_quality, 1),
        }}
        Path(output).write_text(json.dumps(report, indent=2))
        click.echo(click.style(f"  Report saved to: {output}", fg="green"))

    sys.exit(1 if total_critical > 0 else 0)


@cli.command()
def demo():
    """Run a demo scan on a deliberately vulnerable Python snippet."""
    click.echo(click.style("\nRunning demo scan on vulnerable code sample...", fg="blue"))
    demo_file = Path("/tmp/pyguard_demo.py")
    demo_file.write_text('''
import os, pickle, hashlib, sqlite3
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
''')
    from click.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(scan, [str(demo_file), "--no-ai", "--verbose"])
    click.echo(result.output)


if __name__ == "__main__":
    cli()
