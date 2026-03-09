"""
AST-based Python code analyzer.
Parses Python source files structurally to detect complexity,
code smells, and quality issues.
"""
import ast
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class FunctionMetrics:
    name: str
    lineno: int
    complexity: int
    loc: int
    args_count: int
    max_nesting: int
    has_docstring: bool
    issues: list[str] = field(default_factory=list)


@dataclass
class FileMetrics:
    path: str
    total_loc: int
    blank_lines: int
    comment_lines: int
    functions: list[FunctionMetrics]
    classes: list[str]
    imports: list[str]
    global_variables: list[str]
    issues: list[str] = field(default_factory=list)


class ComplexityVisitor(ast.NodeVisitor):
    """Calculates cyclomatic complexity for a function."""

    BRANCH_NODES = (
        ast.If, ast.For, ast.While, ast.ExceptHandler,
        ast.With, ast.Assert, ast.comprehension,
    )

    def __init__(self):
        self.complexity = 1
        self.max_nesting = 0
        self._current_nesting = 0

    def visit_If(self, node):
        self.complexity += 1
        self._enter_nesting()
        self.generic_visit(node)
        self._exit_nesting()

    def visit_For(self, node):
        self.complexity += 1
        self._enter_nesting()
        self.generic_visit(node)
        self._exit_nesting()

    def visit_While(self, node):
        self.complexity += 1
        self._enter_nesting()
        self.generic_visit(node)
        self._exit_nesting()

    def visit_ExceptHandler(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_With(self, node):
        self._enter_nesting()
        self.generic_visit(node)
        self._exit_nesting()

    def visit_BoolOp(self, node):
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_comprehension(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def _enter_nesting(self):
        self._current_nesting += 1
        self.max_nesting = max(self.max_nesting, self._current_nesting)

    def _exit_nesting(self):
        self._current_nesting -= 1


class ASTAnalyzer:
    """Analyzes Python source code using AST parsing."""

    COMPLEXITY_THRESHOLD = 10
    LOC_THRESHOLD = 50
    ARGS_THRESHOLD = 5
    NESTING_THRESHOLD = 4

    def analyze_file(self, file_path: str) -> Optional[FileMetrics]:
        path = Path(file_path)
        if not path.exists() or path.suffix != ".py":
            return None

        source = path.read_text(encoding="utf-8", errors="replace")
        return self.analyze_source(source, str(path))

    def analyze_source(self, source: str, path: str = "<string>") -> FileMetrics:
        lines = source.splitlines()
        total_loc = len(lines)
        blank_lines = sum(1 for l in lines if not l.strip())
        comment_lines = sum(1 for l in lines if l.strip().startswith("#"))

        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            return FileMetrics(
                path=path,
                total_loc=total_loc,
                blank_lines=blank_lines,
                comment_lines=comment_lines,
                functions=[],
                classes=[],
                imports=[],
                global_variables=[],
                issues=[f"SyntaxError: {e}"],
            )

        functions = self._extract_functions(tree, lines)
        classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        imports = self._extract_imports(tree)
        global_vars = self._extract_globals(tree)
        file_issues = self._check_file_issues(tree, source, total_loc)

        return FileMetrics(
            path=path,
            total_loc=total_loc,
            blank_lines=blank_lines,
            comment_lines=comment_lines,
            functions=functions,
            classes=classes,
            imports=imports,
            global_variables=global_vars,
            issues=file_issues,
        )

    def _extract_functions(self, tree: ast.AST, lines: list[str]) -> list[FunctionMetrics]:
        results = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            visitor = ComplexityVisitor()
            visitor.visit(node)

            end_line = getattr(node, "end_lineno", node.lineno)
            loc = end_line - node.lineno + 1
            args_count = len(node.args.args) + len(node.args.posonlyargs) + len(node.args.kwonlyargs)
            has_docstring = (
                isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ) if node.body else False

            issues = []
            if visitor.complexity > self.COMPLEXITY_THRESHOLD:
                issues.append(f"High cyclomatic complexity ({visitor.complexity}) — consider breaking into smaller functions")
            if loc > self.LOC_THRESHOLD:
                issues.append(f"Function too long ({loc} lines) — aim for under {self.LOC_THRESHOLD} lines")
            if args_count > self.ARGS_THRESHOLD:
                issues.append(f"Too many arguments ({args_count}) — consider using a dataclass or config object")
            if visitor.max_nesting > self.NESTING_THRESHOLD:
                issues.append(f"Deep nesting ({visitor.max_nesting} levels) — extract logic into helper functions")
            if not has_docstring and not node.name.startswith("_"):
                issues.append("Missing docstring on public function")

            results.append(FunctionMetrics(
                name=node.name,
                lineno=node.lineno,
                complexity=visitor.complexity,
                loc=loc,
                args_count=args_count,
                max_nesting=visitor.max_nesting,
                has_docstring=has_docstring,
                issues=issues,
            ))
        return results

    def _extract_imports(self, tree: ast.AST) -> list[str]:
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")
        return imports

    def _extract_globals(self, tree: ast.AST) -> list[str]:
        globals_ = []
        for node in ast.body if isinstance(tree, ast.Module) else []:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        globals_.append(target.id)
        return globals_

    def _check_file_issues(self, tree: ast.AST, source: str, loc: int) -> list[str]:
        issues = []
        if loc > 500:
            issues.append(f"File too large ({loc} lines) — consider splitting into modules")
        # Detect bare except
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                issues.append(f"Bare 'except:' clause at line {node.lineno} — catch specific exceptions")
        # Detect print statements (should use logging)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "print":
                    issues.append(f"'print()' at line {node.lineno} — use logging module in production code")
                    break
        return issues
