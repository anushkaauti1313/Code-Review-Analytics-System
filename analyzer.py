"""
analyzer.py
-----------
Core static analysis module for the Code Review Analytics System.

Uses:
  - Pylint for issue detection and classification
  - Python's built-in 'ast' module for deep code metrics
  - Rule-based ML placeholder for defect severity prediction
"""

import ast
import subprocess
import json
import os
import tempfile


# ─────────────────────────────────────────────────────────────────────────────
# PYLINT ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def run_pylint(file_path: str) -> tuple[int, int, int, list[dict]]:
    """
    Run Pylint on the given Python file and parse its JSON output.

    Args:
        file_path (str): Absolute path to the Python file to analyse.

    Returns:
        tuple: (critical_count, major_count, minor_count, issues_list)

    Raises:
        FileNotFoundError: If the file does not exist.
        RuntimeError: If Pylint is not installed, times out, or fails.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    command = [
        "py", "-m", "pylint",
        "--output-format=json",
        "--score=no",
        file_path,
    ]

    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Pylint timed out while analysing the file.")
    except FileNotFoundError:
        # Try 'python' as fallback if 'py' is unavailable
        try:
            result = subprocess.run(
                ["python", "-m", "pylint", "--output-format=json", "--score=no", file_path],
                capture_output=True, text=True, timeout=60,
            )
        except Exception:
            raise RuntimeError(
                "Pylint is not installed or not on PATH. Run: pip install pylint"
            )

    if result.returncode == 32:
        raise RuntimeError(f"Pylint failed: {result.stderr.strip() or 'Unknown error.'}")

    raw_json = result.stdout.strip()
    if not raw_json:
        return 0, 0, 0, []

    try:
        issues = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Failed to parse Pylint JSON output: {exc}\nRaw: {raw_json[:500]}"
        )

    return classify_issues(issues)


def classify_issues(issues: list[dict]) -> tuple[int, int, int, list[dict]]:
    """
    Classify Pylint issues into Critical / Major / Minor / Info.

    Pylint types → severity:
        error / fatal   → Critical
        warning         → Major
        convention      → Minor
        refactor        → Minor
        information     → Info  (not counted in WQS)
    """
    critical_count = major_count = minor_count = 0
    annotated: list[dict] = []

    for issue in issues:
        msg_type = issue.get("type", "").lower()

        if msg_type in ("error", "fatal"):
            severity = "Critical"; critical_count += 1
        elif msg_type == "warning":
            severity = "Major"; major_count += 1
        elif msg_type in ("convention", "refactor"):
            severity = "Minor"; minor_count += 1
        else:
            severity = "Info"

        annotated.append({
            "severity": severity,
            "type":     msg_type,
            "line":     issue.get("line",   "N/A"),
            "column":   issue.get("column", "N/A"),
            "symbol":   issue.get("symbol", ""),
            "message":  issue.get("message", ""),
            "module":   issue.get("module", ""),
            "obj":      issue.get("obj", ""),
        })

    return critical_count, major_count, minor_count, annotated


def compute_wqs(critical: int, major: int, minor: int) -> int:
    """
    Compute the Weighted Quality Score (WQS).

    Formula:  WQS = (Critical × 5) + (Major × 3) + (Minor × 1)

    Lower score = better code quality.
    """
    return (critical * 5) + (major * 3) + (minor * 1)


def analyze_code_string(code: str, filename: str = "uploaded_file.py") -> tuple:
    """
    Write code to a temp file, run Pylint, return results.

    Args:
        code (str): Python source code string.
        filename (str): Logical filename for display purposes.

    Returns:
        tuple: (critical_count, major_count, minor_count, issues_list)

    Raises:
        ValueError: If the code string is empty.
        RuntimeError: If Pylint analysis fails.
    """
    if not code.strip():
        raise ValueError("The uploaded file is empty. Please upload a valid Python file.")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = run_pylint(tmp_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# AST DEEP ANALYSIS  (no external dependencies – uses Python stdlib)
# ─────────────────────────────────────────────────────────────────────────────

def ast_deep_analysis(code_str: str) -> dict:
    """
    Perform deep static analysis using Python's built-in AST module.

    Extracts structural metrics without running an external tool:
      - Line count, function count, class count, import count
      - Documentation coverage (functions + classes with docstrings)
      - Average function length and maximum nesting depth
      - Error handling and lambda usage stats

    Args:
        code_str (str): Raw Python source code.

    Returns:
        dict: Comprehensive code-quality metrics.
    """
    metrics = {
        "total_lines":              len(code_str.splitlines()),
        "num_functions":            0,
        "num_classes":              0,
        "num_imports":              0,
        "functions_with_docstring": 0,
        "classes_with_docstring":   0,
        "has_module_docstring":     False,
        "avg_function_length":      0.0,
        "max_nesting_depth":        0,
        "num_try_blocks":           0,
        "num_lambdas":              0,
        "num_comprehensions":       0,
        "num_decorators":           0,
        "doc_coverage_pct":         100.0,
        "parse_error":              None,
    }

    try:
        tree = ast.parse(code_str)
    except SyntaxError as exc:
        metrics["parse_error"] = str(exc)
        return metrics

    # Module-level docstring
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        metrics["has_module_docstring"] = True

    fn_lengths: list[float] = []

    for node in ast.walk(tree):
        # Functions & async functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            metrics["num_functions"] += 1
            metrics["num_decorators"] += len(node.decorator_list)

            # Check for docstring
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                metrics["functions_with_docstring"] += 1

            # Approximate function length via line numbers
            if hasattr(node, "end_lineno"):
                fn_lengths.append(node.end_lineno - node.lineno + 1)

        # Classes
        elif isinstance(node, ast.ClassDef):
            metrics["num_classes"] += 1
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                metrics["classes_with_docstring"] += 1

        # Imports
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            metrics["num_imports"] += 1

        # Error handling
        elif isinstance(node, (ast.Try, ast.TryStar)):
            metrics["num_try_blocks"] += 1

        # Lambdas
        elif isinstance(node, ast.Lambda):
            metrics["num_lambdas"] += 1

        # Comprehensions (list/dict/set/generator)
        elif isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
            metrics["num_comprehensions"] += 1

    if fn_lengths:
        metrics["avg_function_length"] = round(sum(fn_lengths) / len(fn_lengths), 1)

    metrics["max_nesting_depth"] = _calc_max_depth(tree)

    # Documentation coverage
    total_doc = metrics["num_functions"] + metrics["num_classes"]
    if total_doc > 0:
        documented = metrics["functions_with_docstring"] + metrics["classes_with_docstring"]
        metrics["doc_coverage_pct"] = round(documented / total_doc * 100, 1)

    return metrics


def _calc_max_depth(tree: ast.AST) -> int:
    """
    Recursively calculate the maximum nesting depth of control-flow
    and scope-creating constructs (functions, classes, if, for, while,
    with, try) in the AST.

    Returns:
        int: Maximum depth found.
    """
    _NESTING = (
        ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
        ast.If, ast.For, ast.AsyncFor, ast.While,
        ast.With, ast.AsyncWith, ast.Try,
    )
    max_d = [0]

    def visit(node: ast.AST, depth: int) -> None:
        if isinstance(node, _NESTING):
            depth += 1
        if depth > max_d[0]:
            max_d[0] = depth
        for child in ast.iter_child_nodes(node):
            visit(child, depth)

    visit(tree, 0)
    return max_d[0]


# ─────────────────────────────────────────────────────────────────────────────
# ML PLACEHOLDER MODULE
# ─────────────────────────────────────────────────────────────────────────────

def predict_defect_severity(critical: int, major: int, minor: int) -> dict:
    """
    Predict defect severity level using rule-based logic.

    This function acts as a placeholder for an ML-based prediction model.
    In a production system, this would use a trained classifier (e.g.,
    Random Forest or XGBoost) on labelled defect datasets.

    Current implementation uses weighted rule logic to keep it deterministic
    and satisfy the SRS requirement for a predictive module.

    Args:
        critical (int): Number of critical defects detected.
        major    (int): Number of major defects detected.
        minor    (int): Number of minor defects detected.

    Returns:
        dict: {
            "predicted_severity": str,   # "Critical" | "High" | "Medium" | "Low" | "Clean"
            "confidence":         float, # 0.0–1.0 simulated confidence score
            "recommendation":     str,   # actionable suggestion
            "risk_level":         str,   # "🔴" | "🟠" | "🟡" | "🟢"
        }
    """
    wqs = compute_wqs(critical, major, minor)
    total = critical + major + minor

    # Rule-based prediction tiers
    if critical >= 3 or wqs >= 30:
        return {
            "predicted_severity": "Critical",
            "confidence": round(min(0.95, 0.70 + critical * 0.05), 2),
            "recommendation": "Immediate refactoring required — multiple fatal errors present.",
            "risk_level": "🔴",
        }
    elif critical >= 1 or major >= 5 or wqs >= 15:
        return {
            "predicted_severity": "High",
            "confidence": round(min(0.90, 0.65 + major * 0.04), 2),
            "recommendation": "High defect density — address critical and major issues first.",
            "risk_level": "🔴",
        }
    elif major >= 2 or minor >= 10 or wqs >= 8:
        return {
            "predicted_severity": "Medium",
            "confidence": round(min(0.85, 0.55 + minor * 0.02), 2),
            "recommendation": "Moderate issues — fix warnings to improve maintainability.",
            "risk_level": "🟠",
        }
    elif total > 0:
        return {
            "predicted_severity": "Low",
            "confidence": round(min(0.80, 0.50 + total * 0.03), 2),
            "recommendation": "Minor style issues — low risk, but worth cleaning up.",
            "risk_level": "🟡",
        }
    else:
        return {
            "predicted_severity": "Clean",
            "confidence": 0.99,
            "recommendation": "No defects detected. Code meets quality standards.",
            "risk_level": "🟢",
        }


# ─────────────────────────────────────────────────────────────────────────────
# INSIGHTS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def generate_insights(df) -> list[str]:
    """
    Generate automatic textual insights from the history DataFrame.

    Uses simple statistical comparisons — no ML required.

    Args:
        df: pandas DataFrame with columns matching CSV_COLUMNS plus optional extras.

    Returns:
        list[str]: Human-readable insight strings, each starting with an emoji.
    """
    insights = []

    if df is None or df.empty:
        return ["📭 No history data available to generate insights."]

    techniques = df["Technique"].unique().tolist()
    grouped_wqs = df.groupby("Technique")["WQS"].mean()

    # ── Technique effectiveness ──────────────────────────────────────────────
    if len(grouped_wqs) >= 2:
        best_tech  = grouped_wqs.idxmin()
        worst_tech = grouped_wqs.idxmax()
        insights.append(
            f"🏆 **{best_tech}** has the lowest average WQS ({grouped_wqs[best_tech]:.1f}), "
            f"making it the most effective technique in your history."
        )
        if grouped_wqs[worst_tech] > grouped_wqs[best_tech]:
            insights.append(
                f"⚠️ **{worst_tech}** shows the highest average WQS ({grouped_wqs[worst_tech]:.1f}), "
                f"indicating it detects or allows more defects."
            )

    # ── Peer Review specific ─────────────────────────────────────────────────
    peer_df = df[df["Technique"] == "Peer Review"]
    if not peer_df.empty:
        avg_minor_peer = peer_df["Minor"].mean()
        if avg_minor_peer > df["Minor"].mean() * 1.2:
            insights.append(
                f"👥 **Peer Review** tends to capture more minor style issues "
                f"(avg {avg_minor_peer:.1f}), suggesting reviewers flag convention violations."
            )
        avg_wqs_peer = peer_df["WQS"].mean()
        if avg_wqs_peer > df["WQS"].mean():
            insights.append(
                "👥 **Peer Review** shows higher average WQS — this may reflect manual "
                "detection of subjective quality concerns not caught by tools."
            )

    # ── Tool-assisted specific ───────────────────────────────────────────────
    tool_df = df[df["Technique"] == "Tool-assisted Review"]
    if not tool_df.empty:
        avg_critical_tool = tool_df["Critical"].mean()
        if avg_critical_tool > df["Critical"].mean():
            insights.append(
                f"🔧 **Tool-assisted Review** detects more critical defects on average "
                f"({avg_critical_tool:.1f}), demonstrating automated precision."
            )
        avg_minor_tool = tool_df["Minor"].mean()
        if avg_minor_tool > df["Minor"].mean() * 1.1:
            insights.append(
                "🔧 **Tool-assisted Review** detects more minor defects — "
                "automated tools excel at convention and style checking."
            )

    # ── Pull-based specific ──────────────────────────────────────────────────
    pull_df = df[df["Technique"] == "Pull-based Review"]
    if not pull_df.empty:
        avg_wqs_pull = pull_df["WQS"].mean()
        overall_avg  = df["WQS"].mean()
        if abs(avg_wqs_pull - overall_avg) < (overall_avg * 0.2):
            insights.append(
                "🔀 **Pull-based Review** shows moderate, balanced defect detection — "
                "consistent with collaborative code review practices."
            )

    # ── Overall trend ────────────────────────────────────────────────────────
    if len(df) >= 4:
        recent = df.head(min(3, len(df)))["WQS"].mean()
        older  = df.tail(min(3, len(df)))["WQS"].mean()
        if recent < older * 0.85:
            insights.append(
                f"📉 Code quality is **improving** over time — recent avg WQS ({recent:.1f}) "
                f"is lower than earlier avg ({older:.1f})."
            )
        elif recent > older * 1.15:
            insights.append(
                f"📈 Code quality is **declining** — recent avg WQS ({recent:.1f}) "
                f"is higher than earlier avg ({older:.1f}). Consider a code audit."
            )
        else:
            insights.append(
                f"📊 Code quality is **stable** across recent analyses "
                f"(recent avg WQS: {recent:.1f})."
            )

    # ── Defect distribution ──────────────────────────────────────────────────
    total_c = int(df["Critical"].sum())
    total_m = int(df["Major"].sum())
    total_n = int(df["Minor"].sum())
    total_all = total_c + total_m + total_n

    if total_all > 0:
        pct_minor = total_n / total_all * 100
        pct_crit  = total_c / total_all * 100
        if pct_minor > 60:
            insights.append(
                f"📐 {pct_minor:.0f}% of all defects are **minor style issues** — "
                "a linter or auto-formatter (Black, isort) could resolve most of them instantly."
            )
        if pct_crit > 20:
            insights.append(
                f"🚨 {pct_crit:.0f}% of all defects are **critical** — "
                "the codebase has significant error-prone areas that need urgent attention."
            )

    if not insights:
        insights.append("ℹ️ Run more analyses across different techniques to unlock richer insights.")

    return insights


# ─────────────────────────────────────────────────────────────────────────────
# NORMALIZED WQS  (accuracy upgrade)
# ─────────────────────────────────────────────────────────────────────────────

def compute_normalized_wqs(wqs: int, total_lines: int) -> float:
    """
    Compute Normalized WQS (nWQS) — defect weight per 100 lines of code.

    Raw WQS is biased toward larger files (more lines = more issues).
    nWQS corrects this by normalizing against file size, enabling a fair
    comparison between files of different lengths.

    Formula:  nWQS = (WQS / total_lines) × 100

    Interpretation:
        0–5   → Excellent quality density
        5–15  → Good
        15–30 → Moderate
        30+   → High defect density, needs attention

    Args:
        wqs         (int): Raw Weighted Quality Score.
        total_lines (int): Total lines in the file.

    Returns:
        float: Normalized WQS rounded to 2 decimal places.
    """
    if total_lines <= 0:
        return 0.0
    return round(wqs * 100 / total_lines, 2)


def get_nwqs_grade(nwqs: float) -> tuple[str, str, str]:
    """
    Return (letter, hex_color, label) for a given nWQS value.

    This gives a more accurate grade for files of varying sizes.
    """
    if nwqs == 0:
        return "A+", "#00e676", "Perfect — zero defect density"
    elif nwqs <= 5:
        return "A",  "#69f0ae", "Excellent defect density"
    elif nwqs <= 15:
        return "B",  "#40c4ff", "Good defect density"
    elif nwqs <= 30:
        return "C",  "#FFB347", "Moderate defect density"
    elif nwqs <= 50:
        return "D",  "#FF7043", "High defect density — review needed"
    else:
        return "F",  "#FF4C4C", "Critical defect density — urgent refactoring required"


# ─────────────────────────────────────────────────────────────────────────────
# CYCLOMATIC COMPLEXITY  (accuracy upgrade)
# ─────────────────────────────────────────────────────────────────────────────

def compute_cyclomatic_complexity(code_str: str) -> dict:
    """
    Compute McCabe Cyclomatic Complexity for each function in the code.

    Complexity = 1 + number of decision points (if, elif, for, while,
    except, with, assert, boolean operators and/or).

    Complexity scale (per function):
        1–5   → Simple / low risk
        6–10  → Moderate complexity
        11–20 → High complexity — refactoring advised
        21+   → Very high — extremely hard to test

    Args:
        code_str (str): Python source code.

    Returns:
        dict: {
            "per_function":  list[dict],  # name, complexity, risk, line
            "average":       float,
            "max":           int,
            "total":         int,
            "high_risk_fns": int,        # functions with complexity >= 11
            "parse_error":   str | None,
        }
    """
    result = {
        "per_function":  [],
        "average":       0.0,
        "max":           0,
        "total":         0,
        "high_risk_fns": 0,
        "parse_error":   None,
    }

    # Decision-point node types that increase complexity by 1
    _DECISION_NODES = (
        ast.If, ast.For, ast.AsyncFor, ast.While,
        ast.ExceptHandler, ast.With, ast.AsyncWith,
        ast.Assert, ast.comprehension,
    )

    try:
        tree = ast.parse(code_str)
    except SyntaxError as exc:
        result["parse_error"] = str(exc)
        return result

    def _count_complexity(func_node: ast.AST) -> int:
        """Count decision points inside a function node (McCabe method)."""
        count = 1  # base complexity
        for node in ast.walk(func_node):
            if isinstance(node, _DECISION_NODES):
                count += 1
            # Boolean operators: `and`/`or` each add a branch
            elif isinstance(node, ast.BoolOp):
                count += len(node.values) - 1
        return count

    complexities = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cc = _count_complexity(node)
            if cc >= 11:
                risk = "🔴 Very High"
            elif cc >= 6:
                risk = "🟠 High"
            elif cc >= 4:
                risk = "🟡 Moderate"
            else:
                risk = "🟢 Low"

            result["per_function"].append({
                "name":       node.name,
                "line":       node.lineno,
                "complexity": cc,
                "risk":       risk,
            })
            complexities.append(cc)

    if complexities:
        result["average"]       = round(sum(complexities) / len(complexities), 2)
        result["max"]           = max(complexities)
        result["total"]         = sum(complexities)
        result["high_risk_fns"] = sum(1 for c in complexities if c >= 11)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY SCANNER  (accuracy upgrade)
# ─────────────────────────────────────────────────────────────────────────────

import re as _re  # alias to avoid polluting namespace

# Security vulnerability patterns
# Each entry: (regex_pattern, description, risk_level)
_SECURITY_PATTERNS = [
    # Hardcoded secrets
    (_re.compile(r'(?i)password\s*=\s*["\'][^"\']{3,}["\']'),
     "Hardcoded password detected — store secrets in environment variables.", "🔴 Critical"),
    (_re.compile(r'(?i)(secret|api_key|token|access_key)\s*=\s*["\'][^"\']{5,}["\']'),
     "Hardcoded secret/API key — use os.environ or a secrets manager.", "🔴 Critical"),
    # Dangerous built-ins
    (_re.compile(r'\beval\s*\('),
     "Use of eval() executes arbitrary code — use ast.literal_eval() instead.", "🔴 Critical"),
    (_re.compile(r'\bexec\s*\('),
     "Use of exec() is a code injection risk — avoid or strictly validate input.", "🔴 Critical"),
    # Subprocess shell injection
    (_re.compile(r'subprocess\.(run|call|Popen|check_output).*shell\s*=\s*True'),
     "shell=True in subprocess allows shell injection — pass a list instead.", "🟠 High"),
    # Weak cryptography
    (_re.compile(r'hashlib\.(md5|sha1)\s*\('),
     "Weak hash algorithm (MD5/SHA1) — use SHA-256 or SHA-3 for security.", "🟠 High"),
    # Insecure deserialization
    (_re.compile(r'\bpickle\.loads?\s*\('),
     "pickle.load() deserializes untrusted data — use JSON or protobuf instead.", "🟠 High"),
    (_re.compile(r'\byaml\.load\s*\([^,)]*\)(?!\s*,\s*Loader)'),
     "yaml.load() without Loader is unsafe — use yaml.safe_load().", "🟠 High"),
    # SQL injection patterns
    (_re.compile(r'(?i)(execute|cursor)\s*\(\s*[f"\'].*%.*["\']'),
     "Possible SQL injection via string formatting — use parameterized queries.", "🟠 High"),
    (_re.compile(r'(?i)(execute|cursor)\s*\(\s*f"'),
     "f-string in SQL query — high risk of SQL injection.", "🟠 High"),
    # Weak random
    (_re.compile(r'\brandom\.(random|randint|choice|shuffle)\s*\('),
     "random module is not cryptographically secure — use secrets module for security-sensitive values.", "🟡 Medium"),
    # Insecure HTTP
    (_re.compile(r'verify\s*=\s*False'),
     "SSL certificate verification disabled — this allows MITM attacks.", "🟡 Medium"),
    # Debug/dev code
    (_re.compile(r'\bpdb\.set_trace\s*\('),
     "pdb.set_trace() debugger left in code — remove before production.", "🟡 Medium"),
    (_re.compile(r'\bbreakpoint\s*\(\s*\)'),
     "breakpoint() debugging call left in code — remove before production.", "🟡 Medium"),
    # Open file without context manager
    (_re.compile(r'=\s*open\s*\((?![^)]*\bwith\b)'),
     "open() without 'with' statement — file may not be closed on error.", "🟢 Low"),
    # Assert in production code
    (_re.compile(r'^\s*assert\b', _re.MULTILINE),
     "assert statements can be disabled with -O flag — use explicit checks.", "🟢 Low"),
]


def run_security_scan(code_str: str) -> list[dict]:
    """
    Perform a pattern-based security vulnerability scan on Python source code.

    Scans for common OWASP-aligned security issues using regular expressions.
    Does NOT require any external tools — runs entirely in Python.

    Args:
        code_str (str): Raw Python source code.

    Returns:
        list[dict]: Each item has {line, description, risk_level, match}.
                    Empty list if no vulnerabilities found.
    """
    findings = []
    lines = code_str.splitlines()

    for pattern, description, risk_level in _SECURITY_PATTERNS:
        for line_no, line in enumerate(lines, start=1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = pattern.search(line)
            if match:
                findings.append({
                    "line":        line_no,
                    "description": description,
                    "risk_level":  risk_level,
                    "match":       match.group(0)[:60],
                    "code":        stripped[:80],
                })

    # Deduplicate: same pattern on same line
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["line"], f["description"][:30])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


# ─────────────────────────────────────────────────────────────────────────────
# TECHNICAL DEBT ESTIMATOR  (accuracy upgrade)
# ─────────────────────────────────────────────────────────────────────────────

# Time estimates in minutes based on SonarQube-inspired debt model
_DEBT_MINUTES = {
    "Critical": 30,   # ~30 min to fix each critical issue
    "Major":    20,   # ~20 min to fix each major issue
    "Minor":    5,    # ~5 min to fix each minor issue
}


def estimate_technical_debt(
    critical: int, major: int, minor: int,
    hourly_rate: float = 50.0,
) -> dict:
    """
    Estimate the technical debt (time and cost) needed to fix all detected issues.

    Inspired by SonarQube's technical debt model. Gives the team a concrete
    estimate of remediation cost in developer-hours and USD.

    Args:
        critical     (int):   Number of critical defects.
        major        (int):   Number of major defects.
        minor        (int):   Number of minor defects.
        hourly_rate  (float): Assumed developer hourly rate in USD (default $50).

    Returns:
        dict: {
            "total_minutes": int,
            "hours":         float,
            "cost_usd":      float,
            "breakdown":     dict,   # per severity
            "priority_advice": str,
        }
    """
    c_min = critical * _DEBT_MINUTES["Critical"]
    m_min = major    * _DEBT_MINUTES["Major"]
    n_min = minor    * _DEBT_MINUTES["Minor"]
    total_min = c_min + m_min + n_min

    hours    = round(total_min / 60, 2)
    cost_usd = round(hours * hourly_rate, 2)

    if total_min == 0:
        advice = "✅ No technical debt — codebase is clean!"
    elif total_min <= 30:
        advice = "⚡ Quick fix — less than 30 minutes to resolve all issues."
    elif total_min <= 120:
        advice = "🕐 Short sprint — 1–2 hours of focused refactoring needed."
    elif total_min <= 480:
        advice = "📅 Plan a refactoring day — half to full day of work required."
    else:
        advice = "🗓️ Multi-day effort — schedule dedicated technical debt sprints."

    return {
        "total_minutes": total_min,
        "hours":         hours,
        "cost_usd":      cost_usd,
        "breakdown": {
            "Critical": {"count": critical, "minutes": c_min},
            "Major":    {"count": major,    "minutes": m_min},
            "Minor":    {"count": minor,    "minutes": n_min},
        },
        "priority_advice": advice,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DUPLICATE CODE DETECTOR  (accuracy upgrade)
# ─────────────────────────────────────────────────────────────────────────────

def detect_duplicate_code(code_str: str, min_block_lines: int = 4) -> dict:
    """
    Detect duplicate or highly similar code blocks in a Python file.

    Uses a sliding-window hash approach: consecutive normalized lines are
    hashed and duplicates are flagged. This is a lightweight version of
    the copy-paste detection found in tools like PMD CPD.

    Args:
        code_str        (str): Python source code.
        min_block_lines (int): Minimum number of consecutive lines to
                               consider as a duplicate block (default 4).

    Returns:
        dict: {
            "duplicate_blocks": list[dict],  # each has first_line, second_line, lines
            "total_duplicated_lines": int,
            "duplication_pct": float,        # % of total lines that are duplicated
            "has_duplication": bool,
        }
    """
    lines = code_str.splitlines()
    total = len(lines)

    if total < min_block_lines * 2:
        return {
            "duplicate_blocks":       [],
            "total_duplicated_lines": 0,
            "duplication_pct":        0.0,
            "has_duplication":        False,
        }

    def _normalize(line: str) -> str:
        """Strip whitespace and comments for comparison."""
        stripped = line.strip()
        comment_idx = stripped.find("#")
        if comment_idx > 0:
            stripped = stripped[:comment_idx].rstrip()
        return stripped.lower()

    # Build normalized lines (skip blanks/comments/short lines)
    norm = [_normalize(l) for l in lines]

    # Sliding window hash: hash each block of min_block_lines consecutive lines
    block_hashes: dict[str, list[int]] = {}
    for i in range(total - min_block_lines + 1):
        block = "\n".join(norm[i: i + min_block_lines])
        if not block.strip() or len(block) < 30:
            continue
        if block not in block_hashes:
            block_hashes[block] = []
        block_hashes[block].append(i + 1)  # 1-indexed

    # Collect duplicate blocks (appear more than once)
    duplicate_blocks = []
    duplicated_lines_set: set[int] = set()

    for block_text, line_nos in block_hashes.items():
        if len(line_nos) >= 2:
            first, second = line_nos[0], line_nos[1]
            duplicate_blocks.append({
                "first_line":  first,
                "second_line": second,
                "lines":       min_block_lines,
                "preview":     block_text.split("\n")[0][:60],
            })
            for i in range(min_block_lines):
                duplicated_lines_set.add(first + i)
                duplicated_lines_set.add(second + i)

    total_dup = len(duplicated_lines_set)
    return {
        "duplicate_blocks":       duplicate_blocks[:10],   # cap at 10 for display
        "total_duplicated_lines": total_dup,
        "duplication_pct":        round(total_dup / max(total, 1) * 100, 1),
        "has_duplication":        len(duplicate_blocks) > 0,
    }
