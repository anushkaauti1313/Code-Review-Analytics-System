"""
app.py
------
Code Review Analytics System – Weighted Quality Score (WQS) Platform.

Run with:  streamlit run app.py

Pages:
  1. Code Analysis   – Upload/paste code, select technique, run analysis
  2. Visualization   – Charts, trends, technique comparison, insights
  3. History         – Searchable, filterable history with leaderboard

Accuracy Upgrades (v2):
  - Normalized WQS (nWQS) — size-fair defect density metric
  - McCabe Cyclomatic Complexity per function
  - OWASP-aligned Security Vulnerability Scanner (16 patterns)
  - SonarQube-style Technical Debt Estimator
  - Copy-Paste Duplicate Code Detector
"""

import os
import io
import csv
import base64
import datetime
import math

import streamlit as st
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker

from analyzer import (
    analyze_code_string,
    compute_wqs,
    ast_deep_analysis,
    predict_defect_severity,
    generate_insights,
    # ── Accuracy upgrade modules ──────────────────────
    compute_normalized_wqs,
    get_nwqs_grade,
    compute_cyclomatic_complexity,
    run_security_scan,
    estimate_technical_debt,
    detect_duplicate_code,
)

matplotlib.use("Agg")  # Non-interactive backend for Streamlit

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & DATA
# ─────────────────────────────────────────────────────────────────────────────

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "history.csv")

# Extended CSV columns to support Pull-based metadata
CSV_COLUMNS = [
    "Timestamp", "File Name", "Technique",
    "Critical", "Major", "Minor", "WQS",
    "Review Time (min)", "Comment Count",
]

REVIEW_TECHNIQUES = ["Peer Review", "Pull-based Review", "Tool-assisted Review"]
SEVERITY_COLORS   = {"Critical": "#FF4C4C", "Major": "#FFB347", "Minor": "#4CAF50"}

GRADE_TABLE = [
    (0,    "A+", "#00e676", "🏆 Perfect code! Zero issues detected."),
    (10,   "A",  "#69f0ae", "✅ Excellent quality. Very minor polish possible."),
    (25,   "B",  "#40c4ff", "🔵 Good quality. A few things worth cleaning up."),
    (50,   "C",  "#FFB347", "🟡 Moderate quality. Worth addressing warnings."),
    (80,   "D",  "#FF7043", "🟠 Needs improvement. Several issues present."),
    (9999, "F",  "#FF4C4C", "🔴 Poor quality. Urgent attention required."),
]

# Smart fix suggestions mapped to Pylint symbol names (25+ entries)
FIX_SUGGESTIONS = {
    # ── Naming ──────────────────────────────────────────────────────────────
    "invalid-name": {
        "title": "Use Proper Naming Conventions",
        "tip":   "Variables & functions → snake_case. Classes → PascalCase. Constants → UPPER_CASE.",
        "example": (
            "# ❌ Bad:\nX = 5\ndef MyFunc(): pass\n\n"
            "# ✅ Good:\nmax_count = 5\ndef calculate_total(): pass"
        ),
    },
    # ── Docstrings ───────────────────────────────────────────────────────────
    "missing-module-docstring": {
        "title": "Add a Module Docstring",
        "tip":   "Every Python file should open with a docstring describing its purpose.",
        "example": '"""\nModule for user authentication.\nAuthor: ...\nDate: 2024\n"""',
    },
    "missing-function-docstring": {
        "title": "Add Function Docstrings",
        "tip":   "Document what each function does, its parameters, and its return value.",
        "example": (
            "def add(a: int, b: int) -> int:\n"
            '    """\n    Add two integers.\n\n'
            "    Args:\n        a: First number.\n        b: Second number.\n"
            "    Returns:\n        Sum of a and b.\n    \"\"\"\n    return a + b"
        ),
    },
    "missing-class-docstring": {
        "title": "Add Class Docstrings",
        "tip":   "Every class should have a docstring describing its purpose and attributes.",
        "example": (
            "class Animal:\n"
            '    """Represents an animal.\n\n'
            "    Attributes:\n        name (str): Animal's name.\n    \"\"\""
        ),
    },
    # ── Imports ──────────────────────────────────────────────────────────────
    "unused-import": {
        "title": "Remove Unused Imports",
        "tip":   "Unused imports pollute the namespace and slow module loading.",
        "example": "# ❌ import os   # never used\n# ✅ import sys  # only what you need",
    },
    "wildcard-import": {
        "title": "Avoid Wildcard Imports",
        "tip":   "'from module import *' pollutes the namespace. Import only what you need.",
        "example": "# ❌ from math import *\n# ✅ from math import sqrt, pi",
    },
    "wrong-import-order": {
        "title": "Sort Your Imports (PEP 8)",
        "tip":   "Order: stdlib → third-party → local. Use isort to automate this.",
        "example": "import os          # 1. stdlib\nimport requests    # 2. third-party\nfrom myapp import x  # 3. local",
    },
    # ── Variables ────────────────────────────────────────────────────────────
    "unused-variable": {
        "title": "Remove or Use the Variable",
        "tip":   "Prefix with '_' if a variable is intentionally unused.",
        "example": "# ❌ result = compute()  # never used\n# ✅ _, important = get_pair()",
    },
    "undefined-variable": {
        "title": "Fix Undefined Variable",
        "tip":   "Variable referenced before assignment. Check scope and spelling.",
        "example": "# ❌ print(total)  # total never defined\n# ✅ total = 0\n#    print(total)",
    },
    "redefined-outer-name": {
        "title": "Don't Shadow Variables",
        "tip":   "Using the same name as an outer scope variable causes confusion.",
        "example": "# Use a distinct name for loop vars or inner scope vars",
    },
    # ── Style ────────────────────────────────────────────────────────────────
    "line-too-long": {
        "title": "Keep Lines Under 79 Characters (PEP 8)",
        "tip":   "Use implicit continuation inside brackets or an explicit backslash.",
        "example": (
            "# ✅ Implicit continuation:\n"
            "result = (first_value\n"
            "          + second_value\n"
            "          + third_value)"
        ),
    },
    "trailing-whitespace": {
        "title": "Remove Trailing Whitespace",
        "tip":   "Configure your editor to strip trailing spaces on save.",
        "example": '# VSCode: settings.json\n"files.trimTrailingWhitespace": true',
    },
    "multiple-statements": {
        "title": "One Statement Per Line",
        "tip":   "Multiple statements on one line reduce readability and debuggability.",
        "example": "# ❌ if x: do_this(); do_that()\n# ✅\nif x:\n    do_this()\n    do_that()",
    },
    "unnecessary-pass": {
        "title": "Remove Unnecessary 'pass'",
        "tip":   "'pass' is only needed in empty class/function bodies.",
        "example": "# ❌\ndef greet():\n    print('hi')\n    pass\n# ✅\ndef greet():\n    print('hi')",
    },
    # ── Complexity ───────────────────────────────────────────────────────────
    "too-many-branches": {
        "title": "Reduce Branching Complexity",
        "tip":   "Functions with >12 branches are hard to test. Extract helper functions.",
        "example": "def process(data):\n    return _validate(data) or _transform(data)",
    },
    "too-many-locals": {
        "title": "Reduce Local Variables",
        "tip":   "Too many locals indicate a function does too much. Split it.",
        "example": (
            "from dataclasses import dataclass\n\n"
            "@dataclass\nclass Config:\n    host: str\n    port: int"
        ),
    },
    "too-many-statements": {
        "title": "Split Long Functions",
        "tip":   "Functions should do ONE thing. Move unrelated logic to helpers.",
        "example": "def run():\n    _setup()\n    _process()\n    _teardown()",
    },
    "too-many-arguments": {
        "title": "Reduce Function Arguments",
        "tip":   "Use a config object or *args/**kwargs for many parameters.",
        "example": (
            "# ❌ def create_user(name, age, email, phone, city, country)\n\n"
            "@dataclass\nclass UserData:\n    name: str; age: int\n\n"
            "def create_user(data: UserData): ..."
        ),
    },
    "too-many-return-statements": {
        "title": "Simplify Return Logic",
        "tip":   "Too many returns scatter exit points. Use guard clauses or a result variable.",
        "example": (
            "def process(x):\n    if x < 0:\n        return 'negative'\n"
            "    result = compute(x)\n    return result"
        ),
    },
    # ── Error handling ────────────────────────────────────────────────────────
    "broad-except": {
        "title": "Catch Specific Exceptions",
        "tip":   "Bare 'except' or 'except Exception' hides genuine bugs.",
        "example": (
            "# ❌\ntry:\n    ...\nexcept Exception:\n    pass\n\n"
            "# ✅\ntry:\n    value = int(user_input)\nexcept ValueError:\n    print('Invalid number')"
        ),
    },
    "bare-except": {
        "title": "Never Use Bare 'except:'",
        "tip":   "Catches ALL exceptions including SystemExit and KeyboardInterrupt.",
        "example": "# ❌ except:\n# ✅ except (ValueError, TypeError) as e:",
    },
    # ── OOP ──────────────────────────────────────────────────────────────────
    "no-self-use": {
        "title": "Convert to @staticmethod",
        "tip":   "Method doesn't use 'self'. Mark it @staticmethod for clarity.",
        "example": "class Helper:\n    @staticmethod\n    def format(name: str) -> str:\n        return name.strip().title()",
    },
    "attribute-defined-outside-init": {
        "title": "Define All Attributes in __init__",
        "tip":   "All instance attributes must be defined in __init__ for predictability.",
        "example": "class Dog:\n    def __init__(self, name):\n        self.name  = name\n        self.tricks = []  # ✅ defined here",
    },
    # ── Modern Python ─────────────────────────────────────────────────────────
    "consider-using-enumerate": {
        "title": "Use enumerate() Instead of range(len())",
        "tip":   "enumerate() is Pythonic and avoids manual index management.",
        "example": (
            "# ❌\nfor i in range(len(items)):\n    print(i, items[i])\n\n"
            "# ✅\nfor i, item in enumerate(items):\n    print(i, item)"
        ),
    },
    "consider-using-f-string": {
        "title": "Use f-strings for String Formatting",
        "tip":   "f-strings (Python 3.6+) are faster and more readable.",
        "example": (
            "# ❌ 'Hello, %s!' % name\n"
            "# ❌ 'Hello, {}!'.format(name)\n"
            "# ✅ f'Hello, {name}!'"
        ),
    },
    "unreachable": {
        "title": "Remove Unreachable Code",
        "tip":   "Code after return/break/continue/raise never executes.",
        "example": "# ❌\ndef get_x():\n    return 5\n    print('dead code')  # remove this",
    },
    # ── Fatal / Syntax ────────────────────────────────────────────────────────
    "syntax-error": {
        "title": "Fix Syntax Error",
        "tip":   "Check parentheses, colons, quotes, and indentation.",
        "example": "# Common:\n# Missing colon → def foo():\n# Mismatched brackets → (x + y)\n# Wrong indent → use 4 spaces",
    },
}

DEFAULT_FIX = {
    "title": "Check Pylint Documentation",
    "tip":   "Run `pylint --help-msg=<symbol>` in your terminal for full details on this issue.",
    "example": "# Example: pylint --help-msg=invalid-name",
}

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG  (must be first Streamlit call)
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Code Review Analytics | WQS",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL CSS
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0d1117 !important;
    color: #c9d1d9 !important;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #161b22 0%, #0d1117 100%) !important;
    border-right: 1px solid #30363d;
}
[data-testid="stSidebar"] * { color: #c9d1d9 !important; }
.main .block-container { padding: 2rem 2.5rem 4rem; max-width: 1200px; }

h1 { color: #58a6ff !important; font-weight: 700 !important; }
h2 { color: #79c0ff !important; font-weight: 600 !important; }
h3 { color: #a5d6ff !important; font-weight: 500 !important; }

[data-testid="stMetric"] {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 12px; padding: 1rem 1.25rem;
}
[data-testid="stMetricValue"] { color: #58a6ff !important; font-size: 2rem !important; font-weight: 700 !important; }
[data-testid="stMetricLabel"] { color: #8b949e !important; }

.stButton > button {
    background: linear-gradient(135deg, #238636, #2ea043) !important;
    color: #fff !important; border: none !important; border-radius: 8px !important;
    font-weight: 600 !important; padding: 0.5rem 1.4rem !important; transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #2ea043, #3fb950) !important;
    transform: translateY(-1px) !important; box-shadow: 0 4px 15px rgba(46,160,67,0.4) !important;
}
[data-testid="stFileUploader"] {
    background: #161b22; border: 2px dashed #30363d; border-radius: 12px; padding: 1rem;
}
[data-baseweb="select"] > div {
    background-color: #161b22 !important; border-color: #30363d !important; color: #c9d1d9 !important;
}
[data-testid="stDataFrame"] { border-radius: 10px; overflow: hidden; }
[data-testid="stAlert"] { border-radius: 10px; }
hr { border-color: #30363d !important; }
.stTabs [data-baseweb="tab-list"] { background: #161b22; border-radius: 10px; }
.stTabs [data-baseweb="tab"] { color: #8b949e; font-weight: 500; }
.stTabs [aria-selected="true"] { color: #58a6ff !important; border-bottom: 2px solid #58a6ff !important; }
textarea {
    background: #0d1117 !important; color: #c9d1d9 !important;
    border: 1px solid #30363d !important;
    font-family: 'JetBrains Mono', monospace !important;
}
[data-testid="stExpander"] {
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
}
input[type="number"], input[type="text"] {
    background: #161b22 !important;
    color: #c9d1d9 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
}

/* ── Panel card ── */
.panel {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 14px; padding: 1.25rem 1.5rem; margin-bottom: 1.2rem;
}

/* ── Grade ring ── */
.grade-card {
    display: flex; flex-direction: column; align-items: center;
    justify-content: center; padding: 1.2rem;
    background: #161b22; border: 1px solid #30363d; border-radius: 16px;
}
.grade-ring-container { position: relative; width: 130px; height: 130px; margin-bottom: .5rem; }
.grade-ring-svg { transform: rotate(-90deg); }
.grade-letter {
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    font-size: 2.5rem; font-weight: 800; letter-spacing: -1px;
}

/* ── AST metrics grid ── */
.ast-grid { display: flex; flex-wrap: wrap; gap: .6rem; margin-top: .5rem; }
.ast-item {
    background: #0d1117; border: 1px solid #30363d; border-radius: 10px;
    padding: .6rem .9rem; text-align: center; min-width: 105px; flex: 1;
}
.ast-val { font-size: 1.4rem; font-weight: 700; color: #58a6ff; }
.ast-lbl { font-size: .7rem; color: #8b949e; margin-top: .1rem; }

/* ── Fix suggestion cards ── */
.fix-tip { font-size: .85rem; color: #8b949e; margin-bottom: .5rem; }

/* ── What-if bars ── */
.whatif-bar { background: #21262d; border-radius: 999px; height: 10px; overflow: hidden; margin: .3rem 0 .9rem; }
.whatif-fill { height: 100%; border-radius: 999px; }

/* ── Leaderboard rows ── */
.lb-row {
    display: flex; align-items: center; gap: 1rem;
    padding: .5rem .75rem; border-radius: 8px;
    border: 1px solid #30363d; margin-bottom: .4rem; background: #0d1117;
}
.lb-rank { font-size: 1.1rem; font-weight: 700; min-width: 28px; }
.lb-name { flex: 1; font-size: .88rem; color: #c9d1d9; word-break: break-all; }
.lb-wqs  { font-size: 1rem; font-weight: 700; min-width: 45px; text-align: right; }

/* ── Badges ── */
.badge { display: inline-block; padding: .25em .75em; border-radius: 999px; font-size: .8rem; font-weight: 600; margin: 0 .2em; }
.badge-critical { background:#3d1f1f; color:#FF4C4C; border:1px solid #FF4C4C; }
.badge-major    { background:#3d2e1a; color:#FFB347; border:1px solid #FFB347; }
.badge-minor    { background:#1a3020; color:#4CAF50; border:1px solid #4CAF50; }
.badge-info     { background:#1a2540; color:#58a6ff; border:1px solid #58a6ff; }

/* ── Roadmap steps ── */
.roadmap-step {
    border: 1px solid #30363d; border-radius: 10px;
    padding: .75rem 1rem; margin-bottom: .5rem;
    background: #0d1117; position: relative;
}
.step-num {
    display: inline-flex; align-items: center; justify-content: center;
    width: 26px; height: 26px; border-radius: 50%;
    font-size: .78rem; font-weight: 700; margin-right: .5rem;
}

/* ── Insight card ── */
.insight-card {
    background: #161b22; border: 1px solid #30363d;
    border-left: 4px solid #58a6ff;
    border-radius: 10px; padding: .85rem 1.2rem; margin-bottom: .6rem;
    font-size: .9rem; line-height: 1.6;
}

/* ── ML prediction card ── */
.ml-card {
    background: linear-gradient(135deg, #161b22, #0d1629);
    border: 1px solid #30363d; border-radius: 14px;
    padding: 1.25rem 1.5rem; margin-top: .6rem;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def ensure_history_file() -> None:
    """Create history CSV with headers if it doesn't exist."""
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=CSV_COLUMNS).writeheader()
    else:
        # Migrate old CSV without extra columns by rewriting with new headers if needed
        try:
            df = pd.read_csv(HISTORY_FILE)
            for col in CSV_COLUMNS:
                if col not in df.columns:
                    df[col] = ""
            df.to_csv(HISTORY_FILE, index=False)
        except Exception:
            pass


def save_result(
    file_name: str, technique: str,
    critical: int, major: int, minor: int, wqs: int,
    review_time: float = 0.0, comment_count: int = 0,
) -> None:
    """Append a result row to the history CSV."""
    ensure_history_file()
    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=CSV_COLUMNS).writerow({
            "Timestamp":         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "File Name":         file_name,
            "Technique":         technique,
            "Critical":          critical,
            "Major":             major,
            "Minor":             minor,
            "WQS":               wqs,
            "Review Time (min)": review_time,
            "Comment Count":     comment_count,
        })


def load_history() -> pd.DataFrame:
    """Load history CSV and return DataFrame (newest first)."""
    ensure_history_file()
    try:
        df = pd.read_csv(HISTORY_FILE)
        # Ensure all expected columns exist
        for col in CSV_COLUMNS:
            if col not in df.columns:
                df[col] = 0
        # Sort newest first
        if not df.empty:
            df = df.iloc[::-1].reset_index(drop=True)
        return df if not df.empty else pd.DataFrame(columns=CSV_COLUMNS)
    except Exception:
        return pd.DataFrame(columns=CSV_COLUMNS)


def clear_history() -> None:
    """Overwrite history CSV keeping only the header row."""
    with open(HISTORY_FILE, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=CSV_COLUMNS).writeheader()


# ─────────────────────────────────────────────────────────────────────────────
# GRADE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_grade(wqs: int) -> tuple[str, str, str]:
    """Return (letter, hex_color, tip_text) for a given WQS."""
    for threshold, letter, color, tip in GRADE_TABLE:
        if wqs <= threshold:
            return letter, color, tip
    return "F", "#FF4C4C", "🔴 Poor quality. Urgent attention required."


def grade_ring_html(letter: str, color: str, pct: float) -> str:
    """Generate an SVG grade ring HTML snippet."""
    r = 54; cx = cy = 65
    circ = 2 * math.pi * r
    dash = circ * pct; gap = circ - dash
    return f"""
<div class="grade-card">
  <div class="grade-ring-container">
    <svg class="grade-ring-svg" width="130" height="130" viewBox="0 0 130 130">
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#21262d" stroke-width="10"/>
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="10"
        stroke-linecap="round" stroke-dasharray="{dash:.2f} {gap:.2f}"/>
    </svg>
    <div class="grade-letter" style="color:{color};">{letter}</div>
  </div>
</div>"""


# ─────────────────────────────────────────────────────────────────────────────
# CHART UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _dark(fig, ax, grid_axis="y"):
    """Apply dark theme styling to a matplotlib figure/axes."""
    fig.patch.set_facecolor("#0d1117"); ax.set_facecolor("#161b22")
    for sp in ax.spines.values(): sp.set_edgecolor("#30363d")
    ax.tick_params(colors="#c9d1d9")
    ax.xaxis.label.set_color("#c9d1d9"); ax.yaxis.label.set_color("#c9d1d9")
    ax.title.set_color("#c9d1d9")
    if grid_axis:
        ax.grid(axis=grid_axis, color="#30363d", linewidth=0.6, linestyle="--")
    ax.set_axisbelow(True)


def create_bar_chart(critical, major, minor):
    """Vertical bar chart for defect counts by severity."""
    fig, ax = plt.subplots(figsize=(5, 3.5)); _dark(fig, ax)
    cats = ["Critical", "Major", "Minor"]; vals = [critical, major, minor]
    colors = [SEVERITY_COLORS[c] for c in cats]
    bars = ax.bar(cats, vals, color=colors, width=0.45, zorder=3, edgecolor="#0d1117", linewidth=0.8)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05, str(val),
                ha="center", va="bottom", color="#e6edf3", fontsize=11, fontweight="bold")
    ax.set_title("Defect Count by Severity", fontsize=12, fontweight="bold", pad=10)
    ax.set_ylabel("Count"); ax.set_ylim(0, max(vals + [1]) * 1.3)
    fig.tight_layout(pad=1.0); return fig


def create_pie_chart(critical, major, minor):
    """Pie chart showing defect distribution."""
    labels, sizes, colors = [], [], []
    for v, lbl, c in [(critical,"Critical","#FF4C4C"),(major,"Major","#FFB347"),(minor,"Minor","#4CAF50")]:
        if v: labels.append(f"{lbl}\n({v})"); sizes.append(v); colors.append(c)
    fig, ax = plt.subplots(figsize=(4.5, 3.5))
    fig.patch.set_facecolor("#0d1117"); ax.set_facecolor("#0d1117")
    if not sizes:
        ax.text(0.5, 0.5, "No Issues Found 🎉", ha="center", va="center",
                color="#4CAF50", fontsize=13, transform=ax.transAxes); ax.axis("off")
    else:
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%",
            startangle=140, pctdistance=0.75, wedgeprops=dict(edgecolor="#0d1117", linewidth=1.5))
        for t in texts: t.set_color("#c9d1d9"); t.set_fontsize(9)
        for at in autotexts: at.set_color("#0d1117"); at.set_fontsize(9); at.set_fontweight("bold")
    ax.set_title("Defect Distribution", fontsize=12, fontweight="bold", color="#c9d1d9", pad=10)
    fig.tight_layout(pad=1.0); return fig


def create_heatmap(issues: list, total_lines: int):
    """Issue heatmap across line buckets, weighted by severity."""
    if not issues or total_lines <= 0:
        fig, ax = plt.subplots(figsize=(8, 1.5)); _dark(fig, ax, grid_axis=None)
        ax.text(0.5, 0.5, "No issues to map.", ha="center", va="center",
                color="#8b949e", transform=ax.transAxes); ax.axis("off"); return fig
    bucket = max(10, total_lines // 20)
    n = math.ceil(total_lines / bucket)
    counts = [0] * n
    for iss in issues:
        line = iss.get("line", 0)
        if isinstance(line, int) and line > 0:
            idx = min((line-1)//bucket, n-1)
            w = {"Critical":5,"Major":3,"Minor":1}.get(iss.get("severity","Minor"), 1)
            counts[idx] += w
    labels = [f"L{i*bucket+1}–{min((i+1)*bucket, total_lines)}" for i in range(n)]
    fig, ax = plt.subplots(figsize=(max(8, n*0.6), 2.2)); _dark(fig, ax, grid_axis=None)
    im = ax.imshow([counts], aspect="auto", cmap="YlOrRd", vmin=0, vmax=max(counts+[1]))
    ax.set_xticks(range(n)); ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7, color="#c9d1d9")
    ax.set_yticks([])
    ax.set_title("🔥 Issue Heatmap – Code Hotspots (weighted by severity)", fontsize=11, fontweight="bold", pad=8)
    for j, val in enumerate(counts):
        if val > 0:
            ax.text(j, 0, str(val), ha="center", va="center", fontsize=8, fontweight="bold", color="#0d1117")
    cbar = fig.colorbar(im, ax=ax, orientation="vertical", fraction=0.03, pad=0.02)
    cbar.ax.tick_params(colors="#c9d1d9", labelsize=7)
    cbar.set_label("Severity Weight", color="#8b949e", fontsize=8)
    fig.tight_layout(pad=1.2); return fig


def compute_radar_scores(r: dict, ast_m: dict) -> dict:
    """Compute 5 code quality dimensions (0–100, higher = better)."""
    lines = max(ast_m.get("total_lines", 1), 1)
    error_safety  = max(0.0, min(100.0, 100 - r["critical"] / lines * 500))
    warning_free  = max(0.0, min(100.0, 100 - r["major"] / lines * 200))
    style_score   = max(0.0, min(100.0, 100 - r["minor"] / lines * 80))
    doc_score     = float(ast_m.get("doc_coverage_pct", 100.0))
    avg_len       = float(ast_m.get("avg_function_length", 0))
    nesting       = int(ast_m.get("max_nesting_depth", 0))
    simplicity    = max(0.0, min(100.0, 100 - max(0, avg_len - 12) * 2 - max(0, nesting - 4) * 8))
    return {
        "Error\nSafety":  error_safety,
        "Warning\nFree":  warning_free,
        "Style\nScore":   style_score,
        "Docs\nCoverage": doc_score,
        "Simplicity":     simplicity,
    }


def create_radar_chart(scores: dict):
    """5-axis Code DNA radar/spider chart."""
    categories = list(scores.keys())
    vals = list(scores.values())
    N = len(categories)
    vals_plot = vals + [vals[0]]
    angles = [n / float(N) * 2 * math.pi for n in range(N)] + [0.0]
    fig, ax = plt.subplots(figsize=(5, 5), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor("#0d1117"); ax.set_facecolor("#0f1319")
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(["20", "40", "60", "80", "100"], color="#8b949e", size=7)
    ax.grid(color="#30363d", linewidth=0.5); ax.spines["polar"].set_color("#30363d")
    ax.fill(angles, vals_plot, color="#58a6ff", alpha=0.18)
    ax.plot(angles, vals_plot, color="#58a6ff", linewidth=2)
    ax.scatter(angles[:-1], vals[:N], color="#79c0ff", s=45, zorder=5)
    for angle, val in zip(angles[:-1], vals):
        ax.annotate(f"{val:.0f}", xy=(angle, val), xytext=(angle, val + 10),
                    color="#58a6ff", fontsize=8, fontweight="bold", ha="center", va="center")
    ax.set_xticks(angles[:-1]); ax.set_xticklabels(categories, color="#c9d1d9", size=9, fontweight="500")
    ax.set_title("Code DNA Profile", color="#c9d1d9", fontsize=13, fontweight="bold", pad=18)
    fig.tight_layout(); return fig


def create_wqs_compare_chart(df: pd.DataFrame):
    """
    Bar chart: average WQS per review technique.
    Highlights most effective (lowest WQS) in green
    and least effective (highest WQS) in red.
    """
    grouped = df.groupby("Technique")["WQS"].mean().reindex(REVIEW_TECHNIQUES).fillna(0)
    min_val = grouped.min(); max_val = grouped.max()
    bar_colors = []
    for v in grouped.values:
        if v == min_val:
            bar_colors.append("#4CAF50")   # most effective = green
        elif v == max_val and max_val != min_val:
            bar_colors.append("#FF4C4C")   # least effective = red
        else:
            bar_colors.append("#58a6ff")   # neutral

    fig, ax = plt.subplots(figsize=(7, 4)); _dark(fig, ax)
    bars = ax.bar(REVIEW_TECHNIQUES, grouped.values, color=bar_colors,
                  width=0.45, zorder=3, edgecolor="#0d1117", linewidth=0.8)
    for bar, val in zip(bars, grouped.values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                f"{val:.1f}", ha="center", va="bottom", color="#e6edf3",
                fontsize=11, fontweight="bold")

    # Annotate best & worst
    best_tech  = grouped.idxmin()
    worst_tech = grouped.idxmax()
    for i, tech in enumerate(REVIEW_TECHNIQUES):
        if tech == best_tech:
            ax.text(i, grouped[tech] / 2, "✅ Most\nEffective", ha="center", va="center",
                    fontsize=8, fontweight="bold", color="#fff")
        elif tech == worst_tech and max_val != min_val:
            ax.text(i, grouped[tech] / 2, "⚠️ Least\nEffective", ha="center", va="center",
                    fontsize=8, fontweight="bold", color="#fff")

    ax.set_ylabel("Avg WQS (lower = better)")
    ax.set_title("Technique Comparison – Avg WQS per Review Technique", fontsize=12, fontweight="bold")
    ax.set_ylim(0, max(grouped.values) * 1.35 + 1)
    ax.set_xticklabels(REVIEW_TECHNIQUES, fontsize=10, color="#c9d1d9")
    fig.tight_layout(pad=1.0); return fig


def create_compare_stacked_chart(df: pd.DataFrame):
    """Stacked bar chart: avg defect breakdown per technique."""
    grouped = df.groupby("Technique")[["Critical","Major","Minor"]].mean().reindex(REVIEW_TECHNIQUES).fillna(0)
    fig, ax = plt.subplots(figsize=(7, 4)); _dark(fig, ax)
    x = range(len(REVIEW_TECHNIQUES))
    ax.bar(x, grouped["Critical"], 0.5, label="Critical", color=SEVERITY_COLORS["Critical"], zorder=3)
    ax.bar(x, grouped["Major"],    0.5, bottom=grouped["Critical"], label="Major", color=SEVERITY_COLORS["Major"], zorder=3)
    ax.bar(x, grouped["Minor"],    0.5, bottom=grouped["Critical"]+grouped["Major"], label="Minor", color=SEVERITY_COLORS["Minor"], zorder=3)
    ax.set_xticks(list(x)); ax.set_xticklabels(REVIEW_TECHNIQUES, fontsize=10, color="#c9d1d9")
    ax.set_ylabel("Avg Defect Count"); ax.set_title("Avg Defect Breakdown per Technique", fontsize=12, fontweight="bold")
    ax.legend(loc="upper right", facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")
    fig.tight_layout(pad=1.0); return fig


def create_trend_chart(df: pd.DataFrame):
    """WQS trend line over analysis history (oldest → newest)."""
    tdf = df.iloc[::-1].reset_index(drop=True)
    tdf["Entry"] = range(1, len(tdf)+1)
    fig, ax = plt.subplots(figsize=(9, 3.5)); _dark(fig, ax)

    # Plot per-technique lines if multiple techniques present
    tech_colors = {
        "Peer Review":         "#FFB347",
        "Pull-based Review":   "#58a6ff",
        "Tool-assisted Review":"#4CAF50",
    }
    has_multi = tdf["Technique"].nunique() > 1
    if has_multi:
        for tech, color in tech_colors.items():
            sub = tdf[tdf["Technique"] == tech]
            if not sub.empty:
                ax.plot(sub["Entry"], sub["WQS"], color=color, linewidth=1.5,
                        marker="o", markersize=4, label=tech)
        ax.legend(facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9", fontsize=8)
    else:
        ax.plot(tdf["Entry"], tdf["WQS"], color="#58a6ff", linewidth=2,
                marker="o", markersize=5, markerfacecolor="#79c0ff")
        ax.fill_between(tdf["Entry"], tdf["WQS"], alpha=0.12, color="#58a6ff")

    ax.set_xlabel("Analysis #"); ax.set_ylabel("WQS")
    ax.set_title("WQS Trend Over Time (lower = better)", fontsize=12, fontweight="bold")
    fig.tight_layout(pad=1.0); return fig


def create_defect_dist_chart(df: pd.DataFrame):
    """Overall defect distribution across all history as a grouped bar chart."""
    total_c = int(df["Critical"].sum())
    total_m = int(df["Major"].sum())
    total_n = int(df["Minor"].sum())

    fig, ax = plt.subplots(figsize=(5, 3.5)); _dark(fig, ax)
    cats = ["Critical", "Major", "Minor"]; vals = [total_c, total_m, total_n]
    colors = [SEVERITY_COLORS[c] for c in cats]
    bars = ax.bar(cats, vals, color=colors, width=0.45, zorder=3, edgecolor="#0d1117")
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                str(val), ha="center", va="bottom", color="#e6edf3", fontsize=11, fontweight="bold")
    ax.set_title("Total Defect Distribution (All History)", fontsize=12, fontweight="bold", pad=10)
    ax.set_ylabel("Total Count"); ax.set_ylim(0, max(vals + [1]) * 1.3)
    fig.tight_layout(pad=1.0); return fig


def create_tech_radar_chart(df: pd.DataFrame):
    """Radar chart: per-technique quality score."""
    N = len(REVIEW_TECHNIQUES)
    vals_plot = []
    for tech in REVIEW_TECHNIQUES:
        sub = df[df["Technique"] == tech]
        if sub.empty:
            vals_plot.append(0)
        else:
            avg_wqs = sub["WQS"].mean()
            score = max(0, min(100, 100 - avg_wqs))
            vals_plot.append(round(score, 1))

    vals_plot_closed = vals_plot + [vals_plot[0]]
    angles = [n / float(N) * 2 * math.pi for n in range(N)] + [0.0]
    short_labels = ["Peer\nReview", "Pull-based\nReview", "Tool-assisted\nReview"]

    fig, ax = plt.subplots(figsize=(5, 5), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor("#0d1117"); ax.set_facecolor("#0f1319")
    ax.set_ylim(0, 100); ax.set_yticks([25, 50, 75, 100])
    ax.set_yticklabels(["25","50","75","100"], color="#8b949e", size=7)
    ax.grid(color="#30363d", linewidth=0.5); ax.spines["polar"].set_color("#30363d")
    ax.fill(angles, vals_plot_closed, color="#FFB347", alpha=0.2)
    ax.plot(angles, vals_plot_closed, color="#FFB347", linewidth=2)
    ax.scatter(angles[:-1], vals_plot[:N], color="#FFD580", s=55, zorder=5)
    for angle, val in zip(angles[:-1], vals_plot):
        ax.annotate(f"{val:.0f}", xy=(angle, val), xytext=(angle, val + 10),
                    color="#FFB347", fontsize=9, fontweight="bold", ha="center", va="center")
    ax.set_xticks(angles[:-1]); ax.set_xticklabels(short_labels, color="#c9d1d9", size=9)
    ax.set_title("Technique Quality Radar\n(higher = better avg score)", color="#c9d1d9", fontsize=12, fontweight="bold", pad=18)
    fig.tight_layout(); return fig


def create_batch_chart(batch_df: pd.DataFrame):
    """Horizontal bar chart for batch analysis WQS comparison."""
    fig, ax = plt.subplots(figsize=(7, max(3, len(batch_df) * 0.6))); _dark(fig, ax, grid_axis="x")
    colors = [get_grade(int(w))[1] for w in batch_df["WQS"]]
    y_pos  = range(len(batch_df))
    ax.barh(list(y_pos), batch_df["WQS"].tolist(), color=colors, edgecolor="#0d1117", zorder=3)
    ax.set_yticks(list(y_pos)); ax.set_yticklabels(batch_df["File Name"].tolist(), color="#c9d1d9", fontsize=9)
    ax.invert_yaxis()
    for i, (wqs, grade) in enumerate(zip(batch_df["WQS"], batch_df["Grade"])):
        c = get_grade(int(wqs))[1]
        ax.text(wqs + 0.5, i, f"  {grade}  WQS:{wqs}", va="center", color=c, fontsize=9, fontweight="bold")
    ax.set_xlabel("WQS Score (lower = better)")
    ax.set_title("Batch Analysis – WQS Comparison", fontsize=12, fontweight="bold")
    fig.tight_layout(pad=1.2); return fig


# ─────────────────────────────────────────────────────────────────────────────
# MISC UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def fig_to_base64(fig) -> str:
    """Convert a matplotlib figure to base64 PNG string for HTML embedding."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=120)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def get_top_fixes(issues: list, max_unique: int = 6) -> list[dict]:
    """Return top unique fix suggestions for the detected issues."""
    seen: set[str] = set(); result = []
    for iss in issues:
        sym = iss.get("symbol", "")
        if sym not in seen:
            seen.add(sym)
            fix = {**FIX_SUGGESTIONS.get(sym, DEFAULT_FIX), "symbol": sym, "severity": iss.get("severity","Info")}
            result.append(fix)
        if len(result) >= max_unique:
            break
    return result


def quality_score_10(wqs: int) -> float:
    """Convert WQS to a 0–10 readability score (like Pylint's own score)."""
    return round(max(0.0, 10.0 - wqs / 10.0), 2)


# ─────────────────────────────────────────────────────────────────────────────
# HTML GENERATORS (Audit Report & Quality Certificate)
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(r: dict) -> str:
    """Generate a full HTML audit report for download."""
    letter, color, tip = get_grade(r["wqs"])
    _sev_colors = {"Critical": "#FF4C4C", "Major": "#FFB347", "Minor": "#4CAF50"}
    rows = "".join(
        "<tr>"
        f"<td style='color:{_sev_colors.get(i.get('severity','Info'),'#58a6ff')};font-weight:700'>{i.get('severity','')}</td>"
        f"<td>{i.get('line','N/A')}</td>"
        f"<td><code>{i.get('symbol','')}</code></td>"
        f"<td>{i.get('message','')}</td>"
        "</tr>"
        for i in r.get("issues", [])
    )
    bar_img = pie_img = hm_img = ""
    try:
        fb = create_bar_chart(r["critical"], r["major"], r["minor"]); bar_img = fig_to_base64(fb); plt.close(fb)
        fp = create_pie_chart(r["critical"], r["major"], r["minor"]); pie_img = fig_to_base64(fp); plt.close(fp)
        fh = create_heatmap(r.get("issues",[]), r.get("code_lines",100)); hm_img = fig_to_base64(fh); plt.close(fh)
    except Exception:
        pass
    qs = quality_score_10(r["wqs"])
    ast_m = r.get("ast", {})
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Code Quality Report – {r['file_name']}</title>
<style>body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem;}}
h1{{color:#58a6ff;}}h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:.3rem;}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.2rem;}}
.grade{{font-size:4rem;font-weight:900;color:{color};}}.metric{{display:inline-block;text-align:center;padding:.8rem 1.2rem;
background:#0d1117;border:1px solid #30363d;border-radius:10px;margin:.3rem;}}
.metric .val{{font-size:1.8rem;font-weight:700;color:#58a6ff;}}.metric .lbl{{font-size:.78rem;color:#8b949e;}}
.ast-grid{{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.5rem;}}
.ast-item{{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:.5rem .8rem;text-align:center;min-width:90px;}}
.av{{font-size:1.3rem;font-weight:700;color:#58a6ff;}}.al{{font-size:.7rem;color:#8b949e;}}
table{{width:100%;border-collapse:collapse;}}th{{background:#21262d;color:#8b949e;padding:.5rem;text-align:left;font-size:.82rem;}}
td{{padding:.5rem;border-bottom:1px solid #21262d;font-size:.82rem;}}img{{border-radius:8px;max-width:100%;}}
footer{{text-align:center;color:#30363d;font-size:.75rem;margin-top:2rem;}}</style></head><body>
<h1>🔍 Code Quality Audit Report</h1>
<div class="card"><p><b>File:</b> {r['file_name']} &emsp; <b>Technique:</b> {r['technique']} &emsp; <b>Lines:</b> {ast_m.get('total_lines','?')} &emsp; <b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</p></div>
<h2>📋 Grade & Score</h2>
<div class="card" style="display:flex;align-items:center;gap:2rem;"><div class="grade">{letter}</div>
<div><div style="font-size:1.5rem;font-weight:700;color:{color};">WQS = {r['wqs']}</div>
<div style="color:#8b949e;">Quality Score: <b style="color:#58a6ff;">{qs}/10</b></div>
<div style="margin-top:.5rem;">{tip}</div></div></div>
<h2>📊 Defect Metrics</h2>
<div class="card">
<div class="metric"><div class="val" style="color:#FF4C4C;">{r['critical']}</div><div class="lbl">Critical</div></div>
<div class="metric"><div class="val" style="color:#FFB347;">{r['major']}</div><div class="lbl">Major</div></div>
<div class="metric"><div class="val" style="color:#4CAF50;">{r['minor']}</div><div class="lbl">Minor</div></div>
<div class="metric"><div class="val">{r['wqs']}</div><div class="lbl">WQS</div></div>
<div class="metric"><div class="val" style="color:#58a6ff;">{qs}</div><div class="lbl">Score/10</div></div></div>
<h2>🧬 AST Code Metrics</h2>
<div class="card"><div class="ast-grid">
<div class="ast-item"><div class="av">{ast_m.get('total_lines','?')}</div><div class="al">Total Lines</div></div>
<div class="ast-item"><div class="av">{ast_m.get('num_functions','?')}</div><div class="al">Functions</div></div>
<div class="ast-item"><div class="av">{ast_m.get('num_classes','?')}</div><div class="al">Classes</div></div>
<div class="ast-item"><div class="av">{ast_m.get('num_imports','?')}</div><div class="al">Imports</div></div>
<div class="ast-item"><div class="av">{ast_m.get('doc_coverage_pct','?')}%</div><div class="al">Doc Coverage</div></div>
<div class="ast-item"><div class="av">{ast_m.get('avg_function_length','?')}</div><div class="al">Avg Fn Length</div></div>
<div class="ast-item"><div class="av">{ast_m.get('max_nesting_depth','?')}</div><div class="al">Max Nesting</div></div>
<div class="ast-item"><div class="av">{'✅' if ast_m.get('has_module_docstring') else '❌'}</div><div class="al">Module Doc</div></div>
</div></div>
<h2>📈 Visualizations</h2><div style="display:flex;gap:1rem;flex-wrap:wrap;">
{"<img src='data:image/png;base64,"+bar_img+"' style='height:240px;'/>" if bar_img else ""}
{"<img src='data:image/png;base64,"+pie_img+"' style='height:240px;'/>" if pie_img else ""}
</div>{"<div style='margin-top:1rem;'><img src='data:image/png;base64,"+hm_img+"'/></div>" if hm_img else ""}
<h2>🐛 All Issues ({len(r.get('issues',[]))} total)</h2>
<div class="card" style="overflow-x:auto;"><table>
<tr><th>Severity</th><th>Line</th><th>Symbol</th><th>Message</th></tr>
{rows or "<tr><td colspan='4' style='text-align:center;color:#4CAF50;'>No issues detected 🎉</td></tr>"}
</table></div>
<footer>Generated by Code Review Analytics System | WQS = (C×5)+(M×3)+(m×1)</footer>
</body></html>"""


def generate_certificate_html(r: dict) -> str:
    """Generate a quality certificate HTML page for download."""
    letter, color, tip = get_grade(r["wqs"])
    today = datetime.datetime.now().strftime("%B %d, %Y")
    qs = quality_score_10(r["wqs"])
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Code Quality Certificate</title>
<style>@import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@400;700&family=Inter:wght@300;400;600&display=swap');
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#060b10;display:flex;justify-content:center;align-items:center;min-height:100vh;font-family:'Inter',sans-serif;padding:2rem;}}
.cert{{background:linear-gradient(135deg,#161b22 0%,#0d1117 40%,#161b22 100%);border:3px solid {color};border-radius:20px;
padding:3.5rem 4rem;max-width:760px;width:100%;text-align:center;position:relative;
box-shadow:0 0 80px {color}44,inset 0 0 80px rgba(0,0,0,0.4);}}
.cert::before{{content:'';position:absolute;inset:10px;border:1px solid {color}44;border-radius:14px;pointer-events:none;}}
.watermark{{font-family:'Cinzel',serif;font-size:6rem;color:{color}18;position:absolute;
top:50%;left:50%;transform:translate(-50%,-50%) rotate(-15deg);white-space:nowrap;z-index:0;font-weight:700;}}
.content{{position:relative;z-index:1;}}
.logo{{font-size:3rem;margin-bottom:.5rem;}}
.issuer{{font-family:'Cinzel',serif;font-size:.82rem;color:#8b949e;letter-spacing:4px;text-transform:uppercase;margin-bottom:1.5rem;}}
.title{{font-family:'Cinzel',serif;font-size:1.9rem;color:#e6edf3;font-weight:700;margin-bottom:.4rem;}}
.subtitle{{color:#8b949e;font-size:.88rem;margin-bottom:2rem;letter-spacing:1px;}}
.certifies{{color:#8b949e;font-size:.88rem;margin-bottom:.5rem;}}
.filename{{font-size:1.5rem;font-weight:700;color:#58a6ff;margin-bottom:1.8rem;word-break:break-all;}}
.grade-d{{display:inline-block;font-size:5rem;font-weight:900;color:{color};text-shadow:0 0 40px {color}88;margin-bottom:.4rem;line-height:1;}}
.grade-label{{color:#8b949e;font-size:.82rem;margin-bottom:1.5rem;letter-spacing:2px;text-transform:uppercase;}}
.stats{{display:flex;justify-content:center;gap:1.5rem;margin-bottom:1.8rem;flex-wrap:wrap;}}
.stat{{text-align:center;padding:.6rem 1rem;background:rgba(255,255,255,0.03);border:1px solid #30363d;border-radius:10px;}}
.sv{{font-size:1.6rem;font-weight:700;}}.sl{{font-size:.72rem;color:#8b949e;margin-top:.2rem;}}
.tip-box{{background:rgba(255,255,255,0.04);border:1px solid {color}44;border-radius:10px;
padding:.75rem 1.5rem;color:#c9d1d9;font-size:.88rem;margin-bottom:1.8rem;border-left:4px solid {color};text-align:left;}}
.footer-row{{display:flex;justify-content:space-between;align-items:flex-end;border-top:1px solid #30363d;padding-top:1.5rem;}}
.seal{{width:72px;height:72px;border-radius:50%;border:3px solid {color};display:flex;align-items:center;justify-content:center;font-size:1.8rem;flex-shrink:0;box-shadow:0 0 20px {color}44;}}
.sig-block{{text-align:left;}}.sig-line{{border-top:1px solid #58a6ff;width:190px;margin-bottom:.3rem;}}
.sig-name{{font-size:.78rem;color:#8b949e;}}
.date-block{{text-align:right;color:#8b949e;font-size:.8rem;line-height:1.7;}}</style>
</head><body><div class="cert">
<div class="watermark">WQS CERTIFIED</div>
<div class="content">
  <div class="logo">🔍</div>
  <div class="issuer">Code Review Analytics System</div>
  <div class="title">Certificate of Code Quality</div>
  <div class="subtitle">Weighted Quality Score (WQS) Static Analysis</div>
  <div class="certifies">This certificate is awarded to the Python source file</div>
  <div class="filename">{r['file_name']}</div>
  <div class="grade-d">{letter}</div>
  <div class="grade-label">Quality Grade &nbsp;·&nbsp; Score {qs}/10</div>
  <div class="stats">
    <div class="stat"><div class="sv" style="color:#FF4C4C;">{r['critical']}</div><div class="sl">Critical</div></div>
    <div class="stat"><div class="sv" style="color:#FFB347;">{r['major']}</div><div class="sl">Major</div></div>
    <div class="stat"><div class="sv" style="color:#4CAF50;">{r['minor']}</div><div class="sl">Minor</div></div>
    <div class="stat"><div class="sv" style="color:{color};">{r['wqs']}</div><div class="sl">WQS Score</div></div>
  </div>
  <div class="tip-box">{tip}</div>
  <div style="color:#8b949e;font-size:.8rem;margin-bottom:1.8rem;">
    Review Technique: <b style="color:#79c0ff;">{r['technique']}</b>
  </div>
  <div class="footer-row">
    <div class="sig-block">
      <div class="sig-line"></div>
      <div class="sig-name">Code Review Analytics System</div>
      <div class="sig-name">Automated Static Analysis Engine</div>
    </div>
    <div class="seal">🏆</div>
    <div class="date-block">
      <div>Date of Issue</div>
      <div style="color:#c9d1d9;font-weight:600;font-size:.9rem;">{today}</div>
      <div style="margin-top:.4rem;font-size:.72rem;">WQS = C×5 + M×3 + m×1</div>
    </div>
  </div>
</div>
</div></body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR NAVIGATION  (3 pages)
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:1rem 0 .5rem;'>
      <span style='font-size:2.5rem;'>🔍</span>
      <h2 style='margin:0;color:#58a6ff;font-size:1.15rem;'>Code Review Analytics</h2>
      <p style='color:#8b949e;font-size:.78rem;margin:0;'>Weighted Quality Score System</p>
    </div>
    <hr style='border-color:#30363d;margin:.75rem 0;'/>
    """, unsafe_allow_html=True)

    if "page" not in st.session_state:
        st.session_state.page = "Code Analysis"

    pages = {
        "💻  Code Analysis":  "Code Analysis",
        "📊  Visualization":  "Visualization",
        "📁  History":        "History",
    }
    for label, key in pages.items():
        btn_type = "primary" if st.session_state.page == key else "secondary"
        if st.sidebar.button(label, use_container_width=True, type=btn_type, key=f"nav_{key}"):
            st.session_state.page = key

    st.markdown("<hr style='border-color:#30363d;margin:1rem 0;'/>", unsafe_allow_html=True)
    st.markdown("""
    <div style='font-size:.78rem;color:#8b949e;'>
    <b style='color:#c9d1d9;'>WQS Formula</b><br/>
    <code style='color:#79c0ff;'>WQS = C×5 + M×3 + m×1</code><br/><br/>
    <span style='color:#FF4C4C;'>● Critical</span> (×5) – Errors<br/>
    <span style='color:#FFB347;'>● Major</span> (×3) – Warnings<br/>
    <span style='color:#4CAF50;'>● Minor</span> (×1) – Convention<br/><br/>
    <b style='color:#c9d1d9;'>Grade Scale</b><br/>
    🏆 A+ = WQS 0 (Perfect)<br/>
    ✅ A  ≤ 10 &nbsp; 🔵 B ≤ 25<br/>
    🟡 C  ≤ 50 &nbsp; 🟠 D ≤ 80<br/>
    🔴 F  &gt; 80
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1: CODE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

if st.session_state.page == "Code Analysis":

    st.markdown("""
    <h1 style='margin-bottom:0;'>💻 Code Analysis</h1>
    <p style='color:#8b949e;margin-top:.25rem;'>
      Upload a .py file or paste code, choose a review technique, and get a full quality breakdown.
    </p>
    """, unsafe_allow_html=True)
    st.markdown("---")

    col_input, col_tech = st.columns([2, 1], gap="large")

    # ── Input panel ───────────────────────────────────────────────────────────
    with col_input:
        st.markdown("#### 📂 Input Python Code")
        tab_upload, tab_paste = st.tabs(["⬆️ Upload File", "📋 Paste Code"])
        with tab_upload:
            uploaded_file = st.file_uploader(
                "Choose a .py file", type=["py"],
                label_visibility="collapsed",
                help="Only .py files are accepted.",
            )
        with tab_paste:
            paste_code_raw = st.text_area(
                "Paste Python code", height=200,
                placeholder="# paste your Python code here...\ndef hello():\n    print('Hello!')",
                label_visibility="collapsed", key="paste_area",
            )
            paste_filename = st.text_input(
                "Filename (for records)", value="pasted_code.py", key="paste_fn"
            )

    # ── Technique panel ───────────────────────────────────────────────────────
    with col_tech:
        st.markdown("#### 🔧 Review Technique")
        technique = st.selectbox(
            "Technique", REVIEW_TECHNIQUES,
            label_visibility="collapsed",
            key="technique_select",
        )

        # Dynamic description
        tech_desc = {
            "Peer Review": "👥 Manual defect counts — Pylint is **not** run. You enter Critical, Major and Minor defects yourself.",
            "Pull-based Review": "🔀 Pylint runs. Additionally captures **review time** and **comment count** as metadata.",
            "Tool-assisted Review": "🔧 Full Pylint static analysis — defects detected automatically.",
        }
        st.markdown(f"""
        <div class='panel' style='margin-top:.6rem;font-size:.82rem;'>
          <b style='color:#58a6ff;'>{technique}</b><br/>
          <span style='color:#8b949e;'>{tech_desc[technique]}</span>
        </div>""", unsafe_allow_html=True)

    # ── Peer Review: manual defect inputs ─────────────────────────────────────
    peer_critical = peer_major = peer_minor = 0
    if technique == "Peer Review":
        st.markdown("---")
        st.markdown("#### 👥 Peer Review — Manual Defect Input")
        st.markdown("""
        <div class='panel' style='border-left:3px solid #FFB347;'>
          <b style='color:#FFB347;'>📝 How Peer Review works in this system:</b><br/>
          <span style='font-size:.85rem;color:#c9d1d9;'>
          Enter the defect counts found by your human reviewers below.
          Pylint will also run <b>silently in the background</b> as a reference — you can
          compare both results side-by-side in the output.
          </span>
        </div>""", unsafe_allow_html=True)
        p1, p2, p3 = st.columns(3)
        peer_critical = p1.number_input("🔴 Critical Defects", min_value=0, step=1, value=0, key="peer_c")
        peer_major    = p2.number_input("🟠 Major Defects",    min_value=0, step=1, value=0, key="peer_m")
        peer_minor    = p3.number_input("🟢 Minor Defects",    min_value=0, step=1, value=0, key="peer_mn")

    # ── Pull-based Review: extra metadata inputs ───────────────────────────────
    pull_review_time = 0.0
    pull_comment_count = 0
    if technique == "Pull-based Review":
        st.markdown("---")
        st.markdown("#### 🔀 Pull-based Review — Review Metadata")
        st.info("ℹ️ Pylint will still run. Optionally record PR-level metadata.")
        pr1, pr2 = st.columns(2)
        pull_review_time    = pr1.number_input("⏱️ Review Time (minutes)", min_value=0.0, step=0.5, value=0.0, key="pull_time")
        pull_comment_count  = pr2.number_input("💬 Review Comments Count",  min_value=0, step=1,   value=0,   key="pull_cc")

    # ── Run Analysis button ───────────────────────────────────────────────────
    st.markdown("---")
    run_col, _ = st.columns([1, 3])
    with run_col:
        analyse_btn = st.button("🚀  Run Analysis", use_container_width=True, type="primary", key="run_analysis_btn")

    if analyse_btn:
        # ── Resolve code input ─────────────────────────────────────────────
        code_str = file_name = None

        if uploaded_file is not None:
            try:
                code_str  = uploaded_file.read().decode("utf-8")
                file_name = uploaded_file.name
            except UnicodeDecodeError:
                st.error("❌ Cannot decode file — please ensure it is saved in UTF-8 encoding.")
                st.stop()
        elif paste_code_raw and paste_code_raw.strip():
            code_str  = paste_code_raw
            file_name = paste_filename.strip() or "pasted_code.py"
        else:
            st.warning("⚠️ Please upload a .py file or paste code before running the analysis.")
            st.stop()

        # ── Validate Python file ────────────────────────────────────────────
        if file_name and not file_name.endswith(".py"):
            st.error("❌ Only Python (.py) files are supported.")
            st.stop()

        if not code_str or not code_str.strip():
            st.error("❌ The file or pasted code is empty — please provide valid Python source.")
            st.stop()

        # ── Run appropriate analysis per technique ─────────────────────────
        with st.spinner("🔎 Running analysis…"):
            ast_m = ast_deep_analysis(code_str)

            if technique == "Peer Review":
                # Manual defect counts for official WQS
                critical = int(peer_critical)
                major    = int(peer_major)
                minor    = int(peer_minor)
                wqs      = compute_wqs(critical, major, minor)

                # ALWAYS run Pylint in the background as a reference/comparison tool.
                # This ensures real defects are visible even if manual inputs are zero.
                pylint_ref_c = pylint_ref_m = pylint_ref_mn = 0
                pylint_ref_issues = []
                try:
                    pylint_ref_c, pylint_ref_m, pylint_ref_mn, pylint_ref_issues = \
                        analyze_code_string(code_str, filename=file_name)
                except Exception:
                    pass  # Pylint reference is optional — don't block Peer Review

                # Use Pylint issues list so heatmap/fix suggestions still work
                issues = pylint_ref_issues
                save_result(file_name, technique, critical, major, minor, wqs)

            elif technique == "Pull-based Review":
                # Run Pylint + store review metadata
                try:
                    critical, major, minor, issues = analyze_code_string(code_str, filename=file_name)
                except ValueError as e:
                    st.error(f"❌ {e}"); st.stop()
                except RuntimeError as e:
                    st.error(f"❌ Pylint analysis failed: {e}"); st.stop()
                wqs = compute_wqs(critical, major, minor)
                pylint_ref_c = pylint_ref_m = pylint_ref_mn = 0
                pylint_ref_issues = []
                save_result(
                    file_name, technique, critical, major, minor, wqs,
                    review_time=float(pull_review_time),
                    comment_count=int(pull_comment_count),
                )

            else:
                # Tool-assisted Review — full Pylint
                try:
                    critical, major, minor, issues = analyze_code_string(code_str, filename=file_name)
                except ValueError as e:
                    st.error(f"❌ {e}"); st.stop()
                except RuntimeError as e:
                    st.error(f"❌ Pylint analysis failed: {e}"); st.stop()
                wqs = compute_wqs(critical, major, minor)
                pylint_ref_c = pylint_ref_m = pylint_ref_mn = 0
                pylint_ref_issues = []
                save_result(file_name, technique, critical, major, minor, wqs)

            # ── Run ML prediction ───────────────────────────────────────────
            # Use pylint reference counts for ML if manual peer review was all zeros
            ml_input_c = critical if technique != "Peer Review" or critical > 0 else pylint_ref_c
            ml_input_m = major   if technique != "Peer Review" or major   > 0 else pylint_ref_m
            ml_input_mn= minor   if technique != "Peer Review" or minor   > 0 else pylint_ref_mn
            ml_pred = predict_defect_severity(ml_input_c, ml_input_m, ml_input_mn)

            # ── Accuracy upgrade: run all 5 new analysis modules ───────────────
            total_lines = ast_m.get("total_lines", max(len(code_str.splitlines()), 1))
            nwqs        = compute_normalized_wqs(wqs, total_lines)
            nwqs_grade  = get_nwqs_grade(nwqs)           # (letter, color, label)
            complexity  = compute_cyclomatic_complexity(code_str)
            security    = run_security_scan(code_str)
            debt        = estimate_technical_debt(critical, major, minor)
            dup_code    = detect_duplicate_code(code_str)

            # Cache results in session state
            st.session_state["last_result"] = {
                "file_name": file_name, "technique": technique,
                "critical": critical, "major": major, "minor": minor,
                "wqs": wqs, "issues": issues,
                "code_lines": total_lines,
                "ast": ast_m,
                "ml_pred": ml_pred,
                "pull_review_time": pull_review_time if technique == "Pull-based Review" else 0,
                "pull_comment_count": pull_comment_count if technique == "Pull-based Review" else 0,
                # Pylint reference data (always populated for Peer Review)
                "pylint_ref_c":      pylint_ref_c,
                "pylint_ref_m":      pylint_ref_m,
                "pylint_ref_mn":     pylint_ref_mn,
                "pylint_ref_wqs":    compute_wqs(pylint_ref_c, pylint_ref_m, pylint_ref_mn),
                "pylint_ref_issues": pylint_ref_issues,
                # Accuracy upgrade data
                "nwqs":       nwqs,
                "nwqs_grade": nwqs_grade,
                "complexity": complexity,
                "security":   security,
                "debt":       debt,
                "dup_code":   dup_code,
            }
            st.success(f"✅ Analysis complete for **{file_name}**!")

    # ─────────────────────────────────────────────────────────────────────────
    # RESULTS DISPLAY
    # ─────────────────────────────────────────────────────────────────────────

    if "last_result" in st.session_state:
        r     = st.session_state["last_result"]
        ast_m = r.get("ast", {})
        letter, color, tip = get_grade(r["wqs"])
        qs = quality_score_10(r["wqs"])

        st.markdown("---")
        st.markdown("### 📋 Analysis Results")

        # Info banner
        meta_extra = ""
        if r["technique"] == "Pull-based Review":
            meta_extra = (
                f" &emsp;|&emsp; <span style='color:#8b949e;font-size:.82rem;'>REVIEW TIME</span>&nbsp;"
                f"<b style='color:#79c0ff;'>{r.get('pull_review_time',0)} min</b>"
                f" &emsp;|&emsp; <span style='color:#8b949e;font-size:.82rem;'>COMMENTS</span>&nbsp;"
                f"<b style='color:#79c0ff;'>{r.get('pull_comment_count',0)}</b>"
            )

        st.markdown(f"""
        <div class='panel'>
          <span style='color:#8b949e;font-size:.82rem;'>FILE</span>&nbsp;
          <b style='color:#e6edf3;'>{r['file_name']}</b> &emsp;|&emsp;
          <span style='color:#8b949e;font-size:.82rem;'>TECHNIQUE</span>&nbsp;
          <b style='color:#79c0ff;'>{r['technique']}</b> &emsp;|&emsp;
          <span style='color:#8b949e;font-size:.82rem;'>QUALITY SCORE</span>&nbsp;
          <b style='color:#58a6ff;'>{qs}/10</b>{meta_extra}
        </div>""", unsafe_allow_html=True)

        # Grade ring + metrics
        nwqs        = r.get("nwqs", 0.0)
        nwqs_grade  = r.get("nwqs_grade", ("?", "#8b949e", ""))
        nwqs_letter, nwqs_color, nwqs_label = nwqs_grade

        gcol, m1, m2, m3, m4, m5 = st.columns([1.2, 1, 1, 1, 1, 1])
        with gcol:
            st.markdown(grade_ring_html(letter, color, min(r["wqs"]/100, 1.0)), unsafe_allow_html=True)
        m1.metric("🔴 Critical",     r["critical"],           border=True)
        m2.metric("🟠 Major",        r["major"],              border=True)
        m3.metric("🟢 Minor",        r["minor"],              border=True)
        m4.metric("⚖️ WQS",           r["wqs"],               border=True)
        m5.metric("📊 nWQS/100 lines", f"{nwqs:.1f}",          border=True)

        st.markdown(f"""
        <div style='display:flex;gap:.8rem;flex-wrap:wrap;margin-bottom:1rem;'>
          <div class='panel' style='border-left:3px solid {color};flex:1;'>
            <b style='color:{color};'>Raw Grade {letter} &nbsp;·&nbsp; WQS {r['wqs']}</b> &nbsp;—&nbsp; {tip}<br/>
            <span style='font-size:.78rem;color:#8b949e;'>Based on absolute defect count</span>
          </div>
          <div class='panel' style='border-left:3px solid {nwqs_color};flex:1;'>
            <b style='color:{nwqs_color};'>nWQS Grade {nwqs_letter} &nbsp;·&nbsp; {nwqs:.1f} per 100 lines</b><br/>
            <span style='font-size:.78rem;color:#8b949e;'>{nwqs_label} &mdash; size-fair accuracy metric</span>
          </div>
        </div>""", unsafe_allow_html=True)

        # ── Peer Review: comparison panel + zero-input warning ────────────────
        if r["technique"] == "Peer Review":
            pref_c  = r.get("pylint_ref_c",  0)
            pref_m  = r.get("pylint_ref_m",  0)
            pref_mn = r.get("pylint_ref_mn", 0)
            pref_wqs= r.get("pylint_ref_wqs",0)

            # Warn clearly if reviewer entered 0 for everything
            if r["critical"] == 0 and r["major"] == 0 and r["minor"] == 0:
                st.warning(
                    "⚠️ **All manual defect counts are 0** — your WQS shows A+ which may look incorrect "
                    "to your examiner. Please enter the defects your peer reviewer found, OR switch to "
                    "**Tool-assisted Review** to let Pylint detect them automatically."
                )

            # Side-by-side comparison: Peer Review vs Pylint Reference
            st.markdown("#### 👥 Peer Review vs 🔧 Pylint Reference")
            pc1, pc2 = st.columns(2, gap="large")
            peer_wqs_color = get_grade(r["wqs"])[1]
            tool_wqs_color = get_grade(pref_wqs)[1]
            pc1.markdown(f"""
            <div class='panel' style='border-top:3px solid #FFB347;text-align:center;'>
              <div style='color:#8b949e;font-size:.78rem;text-transform:uppercase;letter-spacing:1px;'>👥 Peer Review (Your Input)</div>
              <div style='display:flex;justify-content:center;gap:1.5rem;margin:.8rem 0;'>
                <div><div style='font-size:1.5rem;font-weight:700;color:#FF4C4C;'>{r['critical']}</div><div style='font-size:.72rem;color:#8b949e;'>Critical</div></div>
                <div><div style='font-size:1.5rem;font-weight:700;color:#FFB347;'>{r['major']}</div><div style='font-size:.72rem;color:#8b949e;'>Major</div></div>
                <div><div style='font-size:1.5rem;font-weight:700;color:#4CAF50;'>{r['minor']}</div><div style='font-size:.72rem;color:#8b949e;'>Minor</div></div>
              </div>
              <div style='font-size:1.2rem;font-weight:700;color:{peer_wqs_color};'>WQS = {r['wqs']}</div>
              <div style='font-size:.78rem;color:#8b949e;margin-top:.3rem;'>Official score used for history</div>
            </div>""", unsafe_allow_html=True)
            pc2.markdown(f"""
            <div class='panel' style='border-top:3px solid #58a6ff;text-align:center;'>
              <div style='color:#8b949e;font-size:.78rem;text-transform:uppercase;letter-spacing:1px;'>🔧 Pylint Reference (Automated)</div>
              <div style='display:flex;justify-content:center;gap:1.5rem;margin:.8rem 0;'>
                <div><div style='font-size:1.5rem;font-weight:700;color:#FF4C4C;'>{pref_c}</div><div style='font-size:.72rem;color:#8b949e;'>Critical</div></div>
                <div><div style='font-size:1.5rem;font-weight:700;color:#FFB347;'>{pref_m}</div><div style='font-size:.72rem;color:#8b949e;'>Major</div></div>
                <div><div style='font-size:1.5rem;font-weight:700;color:#4CAF50;'>{pref_mn}</div><div style='font-size:.72rem;color:#8b949e;'>Minor</div></div>
              </div>
              <div style='font-size:1.2rem;font-weight:700;color:{tool_wqs_color};'>WQS = {pref_wqs}</div>
              <div style='font-size:.78rem;color:#8b949e;margin-top:.3rem;'>For reference only — not saved to history</div>
            </div>""", unsafe_allow_html=True)

        # ── ML Prediction card ─────────────────────────────────────────────
        ml = r.get("ml_pred", {})
        if ml:
            risk_level   = ml.get("risk_level", "🟢")
            predicted    = ml.get("predicted_severity", "Clean")
            confidence   = ml.get("confidence", 0.99)
            ml_rec       = ml.get("recommendation", "")
            ml_color_map = {"Critical":"#FF4C4C","High":"#FF7043","Medium":"#FFB347","Low":"#69f0ae","Clean":"#4CAF50"}
            ml_color = ml_color_map.get(predicted, "#58a6ff")
            st.markdown(f"""
            <div class='ml-card'>
              <div style='font-size:.78rem;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:.4rem;'>
                🤖 ML Defect Severity Prediction <span style='font-size:.7rem;color:#30363d;'>(rule-based placeholder)</span>
              </div>
              <div style='display:flex;align-items:center;gap:1rem;'>
                <div style='font-size:2rem;'>{risk_level}</div>
                <div>
                  <div style='font-size:1.1rem;font-weight:700;color:{ml_color};'>{predicted} Severity</div>
                  <div style='font-size:.8rem;color:#8b949e;'>Confidence: <b style='color:{ml_color};'>{confidence*100:.0f}%</b></div>
                </div>
              </div>
              <div style='margin-top:.6rem;font-size:.85rem;color:#c9d1d9;border-left:3px solid {ml_color};padding-left:.75rem;'>
                {ml_rec}
              </div>
            </div>""", unsafe_allow_html=True)

        # ── AST Deep Metrics Panel ──────────────────────────────────────────
        st.markdown("### 🧬 Deep Code Metrics (AST Analysis)")
        if ast_m.get("parse_error"):
            st.warning(f"⚠️ AST parsing failed: {ast_m['parse_error']}")
        else:
            dc = ast_m.get("doc_coverage_pct", 0)
            doc_col = "#4CAF50" if dc >= 80 else "#FFB347" if dc >= 40 else "#FF4C4C"
            md_icon = "✅" if ast_m.get("has_module_docstring") else "❌"
            st.markdown(f"""
            <div class='panel'>
              <div class='ast-grid'>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('total_lines',0)}</div><div class='ast-lbl'>Total Lines</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('num_functions',0)}</div><div class='ast-lbl'>Functions</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('num_classes',0)}</div><div class='ast-lbl'>Classes</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('num_imports',0)}</div><div class='ast-lbl'>Imports</div></div>
                <div class='ast-item'><div class='ast-val' style='color:{doc_col};'>{dc:.0f}%</div><div class='ast-lbl'>Doc Coverage</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('avg_function_length',0)}</div><div class='ast-lbl'>Avg Fn Length</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('max_nesting_depth',0)}</div><div class='ast-lbl'>Max Nesting</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('num_try_blocks',0)}</div><div class='ast-lbl'>Try Blocks</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('num_comprehensions',0)}</div><div class='ast-lbl'>Comprehensions</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('num_lambdas',0)}</div><div class='ast-lbl'>Lambdas</div></div>
                <div class='ast-item'><div class='ast-val'>{md_icon}</div><div class='ast-lbl'>Module Docstring</div></div>
                <div class='ast-item'><div class='ast-val'>{ast_m.get('num_decorators',0)}</div><div class='ast-lbl'>Decorators</div></div>
              </div>
            </div>""", unsafe_allow_html=True)

        # ── Code DNA Radar + Bar + Pie ─────────────────────────────────────
        st.markdown("### 📈 Defect Visualizations")
        radar_scores = compute_radar_scores(r, ast_m)
        rc1, rc2, rc3 = st.columns(3, gap="large")
        with rc1:
            fr = create_radar_chart(radar_scores)
            st.pyplot(fr, use_container_width=True); plt.close(fr)
        with rc2:
            fb = create_bar_chart(r["critical"], r["major"], r["minor"])
            st.pyplot(fb, use_container_width=False); plt.close(fb)
        with rc3:
            fp = create_pie_chart(r["critical"], r["major"], r["minor"])
            st.pyplot(fp, use_container_width=False); plt.close(fp)

        # ── Heatmap (only for Pylint-based techniques) ──────────────────────
        if r["issues"]:
            st.markdown("### 🔥 Issue Heatmap")
            fh = create_heatmap(r["issues"], r.get("code_lines", 100))
            st.pyplot(fh, use_container_width=True); plt.close(fh)

        # ── SECURITY SCANNER PANEL ───────────────────────────────────────────
        sec = r.get("security", [])
        st.markdown("### 🔒 Security Vulnerability Scan")
        risk_border = {"🔴 Critical": "#FF4C4C", "🟠 High": "#FF7043",
                       "🟡 Medium": "#FFB347", "🟢 Low": "#4CAF50"}
        if not sec:
            st.success("🛡️ No security vulnerabilities detected! Code appears secure.")
        else:
            critical_sec = [s for s in sec if "🔴" in s["risk_level"]]
            high_sec     = [s for s in sec if "🟠" in s["risk_level"]]
            sc1, sc2, sc3 = st.columns(3)
            sc1.metric("🔴 Critical Vulns", len(critical_sec), border=True)
            sc2.metric("🟠 High Vulns",     len(high_sec),     border=True)
            sc3.metric("⚠️ Total Findings",  len(sec),          border=True)
            for finding in sec:
                border_c = risk_border.get(finding["risk_level"], "#58a6ff")
                with st.expander(f"{finding['risk_level']}  —  Line {finding['line']}: {finding['description'][:65]}"):
                    st.markdown(f"""
                    <div style='border-left:3px solid {border_c};padding:.5rem 1rem;background:#0d1117;border-radius:0 6px 6px 0;'>
                      <div style='font-size:.82rem;color:#8b949e;'>Line {finding['line']}</div>
                      <div style='margin:.3rem 0;color:#c9d1d9;'>{finding['description']}</div>
                      <code style='color:{border_c};font-size:.8rem;'>{finding.get('match','')}</code>
                    </div>""", unsafe_allow_html=True)

        # ── CYCLOMATIC COMPLEXITY TABLE ──────────────────────────────────────
        cc = r.get("complexity", {})
        st.markdown("### 🧠 Cyclomatic Complexity (McCabe)")
        if cc.get("parse_error"):
            st.warning(f"⚠️ Could not compute complexity: {cc['parse_error']}")
        elif not cc.get("per_function"):
            st.info("ℹ️ No functions found to measure complexity.")
        else:
            cc1, cc2, cc3, cc4 = st.columns(4)
            cc1.metric("🔵 Avg Complexity",    f"{cc['average']:.1f}", border=True)
            cc2.metric("🔴 Max Complexity",    cc["max"],              border=True)
            cc3.metric("⚠️ High Risk Fns",     cc["high_risk_fns"],   border=True)
            cc4.metric("📦 Functions Scanned", len(cc["per_function"]), border=True)
            fn_df = pd.DataFrame(cc["per_function"]).rename(columns={
                "name": "Function", "line": "Line",
                "complexity": "Complexity", "risk": "Risk Level"
            }).sort_values("Complexity", ascending=False).reset_index(drop=True)
            st.dataframe(fn_df, use_container_width=True,
                         height=min(350, 40 * len(fn_df) + 48), hide_index=True)

        # ── TECHNICAL DEBT PANEL ─────────────────────────────────────────────
        debt = r.get("debt", {})
        if debt:
            st.markdown("### 💰 Technical Debt Estimation")
            td1, td2, td3, td4 = st.columns(4)
            td1.metric("⏱️ Total Minutes",  debt["total_minutes"],      border=True)
            td2.metric("🕐 Hours Required", f"{debt['hours']}h",        border=True)
            td3.metric("💵 Est. Cost (USD)", f"${debt['cost_usd']:.0f}", border=True)
            brkd = debt["breakdown"]
            td4.metric("🔴 Critical Mins",  brkd["Critical"]["minutes"], border=True)
            st.markdown(f"""
            <div class='panel' style='border-left:3px solid #58a6ff;'>
              <b style='color:#58a6ff;'>💻 {debt['priority_advice']}</b><br/>
              <span style='font-size:.82rem;color:#8b949e;'>
                Breakdown: {brkd['Critical']['count']} critical ×30min +
                {brkd['Major']['count']} major ×20min +
                {brkd['Minor']['count']} minor ×5min &nbsp;|&nbsp; Rate assumed: $50/hr
              </span>
            </div>""", unsafe_allow_html=True)

        # ── DUPLICATE CODE PANEL ─────────────────────────────────────────────
        dup = r.get("dup_code", {})
        if dup:
            st.markdown("### 🔄 Duplicate Code Detection")
            if not dup.get("has_duplication"):
                st.success("✅ No duplicate code blocks detected.")
            else:
                dp1, dp2 = st.columns(2)
                dp1.metric("🔄 Duplicate Blocks",   len(dup["duplicate_blocks"]), border=True)
                dp2.metric("📋 Duplicated Lines %", f"{dup['duplication_pct']}%",  border=True)
                for blk in dup["duplicate_blocks"]:
                    st.markdown(f"""
                    <div class='panel' style='border-left:3px solid #FFB347;padding:.6rem 1rem;'>
                      <span style='color:#FFB347;font-size:.8rem;font-weight:700;'>🔄 DUPLICATE BLOCK</span>&nbsp;
                      Lines <b style='color:#c9d1d9;'>{blk['first_line']}</b> and
                      <b style='color:#c9d1d9;'>{blk['second_line']}</b>
                      &nbsp;<span style='color:#8b949e;font-size:.78rem;'>({blk['lines']} lines repeated)</span><br/>
                      <code style='color:#8b949e;font-size:.75rem;'>{blk['preview']}</code>
                    </div>""", unsafe_allow_html=True)

        # ── What-If Improvement Simulator ──────────────────────────────────
        st.markdown("### 🔮 What-If Improvement Simulator")
        wqs_now   = r["wqs"]
        wqs_no_c  = compute_wqs(0, r["major"], r["minor"])
        wqs_no_cm = compute_wqs(0, 0, r["minor"])

        def pct_saved(old, new):
            return 0 if old == 0 else int((old - new) / old * 100)

        def whatif_bar_html(val, best, bar_color):
            w = max(0, 100 - int(val / max(best, 1) * 100))
            return f'<div class="whatif-bar"><div class="whatif-fill" style="width:{w}%;background:{bar_color};"></div></div>'

        for name, val, sc, improvement, desc in [
            ("📍 Current State (baseline)", wqs_now, "#8b949e", "baseline",
             f"C{r['critical']} issues, M{r['major']} issues, m{r['minor']} issues"),
            (f"🔴 Fix all {r['critical']} Critical issues", wqs_no_c, "#FF4C4C",
             f"▼ {wqs_now-wqs_no_c} pts saved ({pct_saved(wqs_now,wqs_no_c)}%)",
             "Fixes errors — biggest single impact"),
            (f"🟠 Fix Critical + Major ({r['critical']+r['major']} issues)", wqs_no_cm, "#FFB347",
             f"▼ {wqs_now-wqs_no_cm} pts saved ({pct_saved(wqs_now,wqs_no_cm)}%)",
             "Only minor style issues remain"),
            ("✨ Fix Everything → Perfect Code", 0, "#00e676",
             f"▼ {wqs_now} pts saved (100%)", "WQS = 0, Grade A+"),
        ]:
            gl, gc, _ = get_grade(int(val))
            st.markdown(f"""
            <div class='roadmap-step'>
              <span class='step-num' style='background:{sc}22;color:{sc};border:1px solid {sc}44;'>{gl}</span>
              <b style='color:#c9d1d9;'>{name}</b>
              <span style='float:right;color:{sc};font-weight:700;'>WQS {val}</span><br/>
              <span style='font-size:.82rem;color:#8b949e;margin-left:2rem;'>{desc}</span>
              &nbsp;&nbsp;<span style='font-size:.82rem;color:{sc};'>{improvement}</span>
              {whatif_bar_html(val, wqs_now, sc)}
            </div>""", unsafe_allow_html=True)

        # ── Smart Fix Suggestions ───────────────────────────────────────────
        if r["issues"]:
            st.markdown("### 💡 Smart Fix Suggestions")
            st.markdown("*Top actionable recommendations — click to expand each fix:*")
            top_fixes = get_top_fixes(r["issues"], max_unique=7)
            sev_border = {"Critical":"#FF4C4C","Major":"#FFB347","Minor":"#4CAF50","Info":"#58a6ff"}
            for fix in top_fixes:
                bcolor = sev_border.get(fix.get("severity","Info"), "#58a6ff")
                with st.expander(f"🔧  {fix['title']}  —  `{fix.get('symbol','')}`"):
                    st.markdown(f"""
                    <div style='border-left:3px solid {bcolor};padding:.5rem 1rem;border-radius:0 6px 6px 0;background:#0d1117;'>
                      <span class='badge badge-{fix.get("severity","info").lower()}'>{fix.get("severity","Info")}</span>
                      <code style='color:#8b949e;font-size:.8rem;margin-left:.5rem;'>{fix.get("symbol","")}</code>
                      <p class='fix-tip' style='margin-top:.5rem;'>{fix.get("tip","")}</p>
                    </div>""", unsafe_allow_html=True)
                    if fix.get("example"):
                        st.code(fix["example"], language="python")

        # ── All Issues table ────────────────────────────────────────────────
        if r["issues"]:
            st.markdown("### 🐛 All Detected Issues")
            sev_filter = st.multiselect(
                "Filter by severity",
                ["Critical","Major","Minor","Info"],
                default=["Critical","Major","Minor"],
                key="sev_filter",
            )
            filtered = [i for i in r["issues"] if i["severity"] in sev_filter]
            if filtered:
                st.dataframe(
                    pd.DataFrame([{"Sev.":i["severity"],"Line":i["line"],"Col":i["column"],
                                   "Symbol":i["symbol"],"Message":i["message"]} for i in filtered]),
                    use_container_width=True, height=min(350, 38*len(filtered)+40), hide_index=True,
                )
            else:
                st.info("No issues match the selected filters.")
        else:
            st.success("🎉 No Pylint issues detected!")

        # ── Export ──────────────────────────────────────────────────────────
        st.markdown("---")
        st.markdown("### 📥 Export")
        dl1, dl2 = st.columns(2)
        with dl1:
            st.download_button(
                "📄  Download HTML Audit Report",
                data=generate_html_report(r).encode("utf-8"),
                file_name=f"report_{r['file_name'].replace('.py','')}.html",
                mime="text/html", use_container_width=True,
            )
        with dl2:
            st.download_button(
                "🏆  Download Quality Certificate",
                data=generate_certificate_html(r).encode("utf-8"),
                file_name=f"certificate_{r['file_name'].replace('.py','')}.html",
                mime="text/html", use_container_width=True,
            )


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2: VISUALIZATION
# ─────────────────────────────────────────────────────────────────────────────

elif st.session_state.page == "Visualization":

    st.markdown("""
    <h1 style='margin-bottom:0;'>📊 Visualization Dashboard</h1>
    <p style='color:#8b949e;margin-top:.25rem;'>
      Technique comparison, WQS trends, defect distribution, and automatic insights.
    </p>
    """, unsafe_allow_html=True)
    st.markdown("---")

    df_all = load_history()

    if df_all.empty:
        st.info("📭 No history yet. Run at least one analysis to populate this dashboard.")
        st.stop()

    # ── Technique Comparison ──────────────────────────────────────────────────
    st.markdown("### ⚖️ Technique Comparison")
    if df_all["Technique"].nunique() >= 2:
        tc1, tc2 = st.columns(2, gap="large")
        with tc1:
            fw = create_wqs_compare_chart(df_all)
            st.pyplot(fw, use_container_width=True); plt.close(fw)
        with tc2:
            ftr = create_tech_radar_chart(df_all)
            st.pyplot(ftr, use_container_width=True); plt.close(ftr)

        # Most/Least effective callout
        grouped_wqs = df_all.groupby("Technique")["WQS"].mean()
        best_tech   = grouped_wqs.idxmin()
        worst_tech  = grouped_wqs.idxmax()
        _, best_c, _ = get_grade(int(grouped_wqs[best_tech]))
        _, worst_c, _= get_grade(int(grouped_wqs[worst_tech]))

        ev1, ev2 = st.columns(2)
        ev1.markdown(f"""
        <div class='panel' style='border-top:3px solid {best_c};text-align:center;'>
          <div style='color:#8b949e;font-size:.82rem;'>✅ Most Effective Technique</div>
          <div style='font-size:1.1rem;font-weight:700;color:{best_c};margin:.3rem 0;'>{best_tech}</div>
          <div style='color:#8b949e;'>Avg WQS: <b style='color:{best_c};'>{grouped_wqs[best_tech]:.1f}</b></div>
        </div>""", unsafe_allow_html=True)
        ev2.markdown(f"""
        <div class='panel' style='border-top:3px solid {worst_c};text-align:center;'>
          <div style='color:#8b949e;font-size:.82rem;'>⚠️ Least Effective Technique</div>
          <div style='font-size:1.1rem;font-weight:700;color:{worst_c};margin:.3rem 0;'>{worst_tech}</div>
          <div style='color:#8b949e;'>Avg WQS: <b style='color:{worst_c};'>{grouped_wqs[worst_tech]:.1f}</b></div>
        </div>""", unsafe_allow_html=True)

        # Stacked defect breakdown
        st.markdown("#### 📊 Defect Breakdown by Technique")
        fd = create_compare_stacked_chart(df_all)
        st.pyplot(fd, use_container_width=True); plt.close(fd)

        # Full stats table
        st.markdown("#### 📋 Technique Statistics Table")
        stats = df_all.groupby("Technique").agg(
            Runs       = ("WQS","count"),
            Avg_WQS    = ("WQS","mean"),
            Avg_Score_10=("WQS", lambda x: round(max(0.0, 10 - x.mean()/10), 2)),
            Avg_Critical=("Critical","mean"),
            Avg_Major  = ("Major","mean"),
            Avg_Minor  = ("Minor","mean"),
            Best_WQS   = ("WQS","min"),
            Worst_WQS  = ("WQS","max"),
        ).round(2).reindex(REVIEW_TECHNIQUES).reset_index()
        st.dataframe(stats, use_container_width=True, hide_index=True)

    else:
        st.info("📊 Run analyses with at least **2 different techniques** to see a comparison.")

    # ── WQS Trend Chart ───────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📉 WQS Trend Over Time")
    if len(df_all) >= 2:
        ft = create_trend_chart(df_all)
        st.pyplot(ft, use_container_width=True); plt.close(ft)
    else:
        st.info("ℹ️ Run at least 2 analyses to see a trend.")

    # ── Defect Distribution (all history) ────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🧮 Defect Distribution Across All History")
    dd1, dd2 = st.columns([1, 1], gap="large")
    with dd1:
        fdd = create_defect_dist_chart(df_all)
        st.pyplot(fdd, use_container_width=True); plt.close(fdd)
    with dd2:
        total_c = int(df_all["Critical"].sum())
        total_m = int(df_all["Major"].sum())
        total_n = int(df_all["Minor"].sum())
        total_all = total_c + total_m + total_n
        st.markdown(f"""
        <div class='panel' style='height:100%;'>
          <div style='color:#8b949e;font-size:.82rem;margin-bottom:.8rem;text-transform:uppercase;letter-spacing:1px;'>
            Cumulative Defect Totals
          </div>
          <div class='ast-grid'>
            <div class='ast-item'><div class='ast-val' style='color:#FF4C4C;'>{total_c}</div><div class='ast-lbl'>Total Critical</div></div>
            <div class='ast-item'><div class='ast-val' style='color:#FFB347;'>{total_m}</div><div class='ast-lbl'>Total Major</div></div>
            <div class='ast-item'><div class='ast-val' style='color:#4CAF50;'>{total_n}</div><div class='ast-lbl'>Total Minor</div></div>
            <div class='ast-item'><div class='ast-val'>{total_all}</div><div class='ast-lbl'>Grand Total</div></div>
          </div>
          <div style='margin-top:1rem;font-size:.82rem;color:#8b949e;'>
            Critical: <b style='color:#FF4C4C;'>{total_c/max(total_all,1)*100:.1f}%</b> &nbsp;
            Major: <b style='color:#FFB347;'>{total_m/max(total_all,1)*100:.1f}%</b> &nbsp;
            Minor: <b style='color:#4CAF50;'>{total_n/max(total_all,1)*100:.1f}%</b>
          </div>
        </div>""", unsafe_allow_html=True)

    # ── Insights Module ───────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🧠 Automatic Insights")
    st.markdown("*AI-generated observations from your analysis history:*")
    insights = generate_insights(df_all)
    for ins in insights:
        st.markdown(f"<div class='insight-card'>{ins}</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3: HISTORY
# ─────────────────────────────────────────────────────────────────────────────

elif st.session_state.page == "History":

    st.markdown("""
    <h1 style='margin-bottom:0;'>📁 Analysis History</h1>
    <p style='color:#8b949e;margin-top:.25rem;'>
      All previous scan results — filterable, sortable, and exportable.
    </p>
    """, unsafe_allow_html=True)
    st.markdown("---")

    df = load_history()

    if df.empty:
        st.info("📭 No history yet. Run an analysis first.")
    else:
        # ── Filters ────────────────────────────────────────────────────────
        st.markdown("#### 🔍 Filters")
        f1, f2, f3, f4 = st.columns([2, 2, 1, 1], gap="medium")

        with f1:
            tech_f = st.multiselect(
                "Filter by Technique", REVIEW_TECHNIQUES,
                default=REVIEW_TECHNIQUES, key="hist_tech_f",
            )
        with f2:
            # File name filter
            all_files = sorted(df["File Name"].unique().tolist())
            file_f = st.multiselect(
                "Filter by File Name", all_files,
                default=all_files, key="hist_file_f",
            )
        with f3:
            wqs_max = int(df["WQS"].max()) if "WQS" in df.columns else 0
            wqs_f   = st.slider("Max WQS", 0, max(wqs_max, 1), max(wqs_max, 1), key="hist_wqs_f")
        with f4:
            st.markdown("<br/>", unsafe_allow_html=True)
            if st.button("🗑️  Clear History", type="secondary", use_container_width=True, key="clear_hist_btn"):
                clear_history()
                if "last_result" in st.session_state:
                    del st.session_state["last_result"]
                st.success("History cleared.")
                st.rerun()

        # ── Apply filters ──────────────────────────────────────────────────
        fdf = df[
            df["Technique"].isin(tech_f) &
            df["File Name"].isin(file_f) &
            (df["WQS"].astype(int) <= wqs_f)
        ].copy()

        st.markdown(f"**{len(fdf)}** record(s) matching filters. *(Latest first)*")
        st.markdown("---")

        if fdf.empty:
            st.warning("⚠️ No records match the selected filters.")
        else:
            # Highlight the most recent row
            def hl_latest(row):
                if row.name == 0:
                    return ["background-color:#1f3a5f;color:#58a6ff;"] * len(row)
                return [""] * len(row)

            display_cols = ["Timestamp","File Name","Technique","Critical","Major","Minor","WQS",
                            "Review Time (min)","Comment Count"]
            show_cols = [c for c in display_cols if c in fdf.columns]
            st.dataframe(
                fdf[show_cols].style.apply(hl_latest, axis=1),
                use_container_width=True,
                height=min(500, 38*len(fdf)+48),
                hide_index=True,
            )

            # ── Summary stats ──────────────────────────────────────────────
            st.markdown("---")
            st.markdown("### 📊 Summary Statistics")
            s1, s2, s3, s4, s5 = st.columns(5)
            s1.metric("Total Analyses", len(fdf))
            s2.metric("Avg WQS",        f"{fdf['WQS'].mean():.1f}")
            s3.metric("Best WQS",       int(fdf["WQS"].min()))
            s4.metric("Worst WQS",      int(fdf["WQS"].max()))
            s5.metric("Total Issues",   int(fdf[["Critical","Major","Minor"]].sum().sum()))

            # ── Leaderboard ────────────────────────────────────────────────
            st.markdown("---")
            st.markdown("### 🏆 Code Quality Leaderboard")
            lb1, lb2 = st.columns(2, gap="large")
            medals = ["🥇","🥈","🥉","4️⃣","5️⃣"]

            with lb1:
                st.markdown("**🥇 Top 5 Best Files** *(lowest WQS)*")
                for rank, (_, row) in enumerate(fdf.nsmallest(5, "WQS").iterrows()):
                    _, c, _ = get_grade(int(row["WQS"]))
                    st.markdown(f"""
                    <div class="lb-row">
                      <span class="lb-rank">{medals[rank]}</span>
                      <span class="lb-name">{row['File Name']}</span>
                      <span style='font-size:.75rem;color:#8b949e;'>
                        <span style='color:#FF4C4C;'>C{int(row['Critical'])}</span>
                        <span style='color:#FFB347;'> M{int(row['Major'])}</span>
                        <span style='color:#4CAF50;'> m{int(row['Minor'])}</span>
                      </span>
                      <span class="lb-wqs" style="color:{c};">{int(row['WQS'])}</span>
                    </div>""", unsafe_allow_html=True)

            with lb2:
                st.markdown("**⚠️ Top 5 Most Defective** *(highest WQS)*")
                for _, (_, row) in enumerate(fdf.nlargest(5, "WQS").iterrows()):
                    _, c, _ = get_grade(int(row["WQS"]))
                    st.markdown(f"""
                    <div class="lb-row" style="border-color:#3d1f1f;">
                      <span class="lb-rank">⚠️</span>
                      <span class="lb-name">{row['File Name']}</span>
                      <span style='font-size:.75rem;color:#8b949e;'>
                        <span style='color:#FF4C4C;'>C{int(row['Critical'])}</span>
                        <span style='color:#FFB347;'> M{int(row['Major'])}</span>
                        <span style='color:#4CAF50;'> m{int(row['Minor'])}</span>
                      </span>
                      <span class="lb-wqs" style="color:{c};">{int(row['WQS'])}</span>
                    </div>""", unsafe_allow_html=True)

            # ── Export filtered CSV ────────────────────────────────────────
            st.markdown("---")
            st.download_button(
                "⬇️  Download Filtered History as CSV",
                data=fdf.to_csv(index=False).encode("utf-8"),
                file_name="code_review_history_filtered.csv",
                mime="text/csv",
            )
