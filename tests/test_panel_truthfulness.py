"""0A.11 remainder: repository-wide panel truthfulness enforcement.

Phase 0A.11 repaired the SERVED panel, but nothing failed if fabricated
paths (Math.random()) or dead controls returned in other panel revisions.
Plan v7.5, AFTER-0A.6 item 1: "Add a repository-wide check that fails if
fabricated metrics or Math.random() return in any panel revision, not only
in the currently served file. Include dead controls in that inventory."

Enforced here:
  1. The served panel is the ONLY panel revision in the repository. Stale
     unserved revisions historically carried fabricated-value paths.
  2. No executable Math.random() anywhere in a panel revision. Comment
     lines documenting the defect are exempt.
  3. Every control in the served panel (apiCall/fetch/href) targets a
     route registered by src.main with a matching HTTP method, and stays
     same-origin (no absolute links to the closed backend host).
"""
import re
from pathlib import Path

from fastapi.routing import APIRoute

REPO_ROOT = Path(__file__).resolve().parents[1]
PANEL_DIR = REPO_ROOT / "docker" / "control-panel"
SERVED = PANEL_DIR / "control-panel.html"

# Unregistered URL fragments historically referenced by panel revisions
# and deliberately retired in the 0A.6/0A.11 work.
RETIRED_TARGETS = {
    "/docs",          # FastAPI docs closed by 0A.6 (development exposure)
    "/api/training/generate-data",   # never registered
    "/api/rules/validate",           # never registered
    "/api/debug/status",             # replaced by /api/panel-status in 0A.6
}

# The browser must never talk to the waf-api backend directly: that would
# bypass the panel proxy (same-origin/trusted-user setup) and 0A.6 auth
# paths. Absolute links to the backend host are therefore dead controls.
BACKEND_HOSTS = ("localhost:8000", "127.0.0.1:8000", "waf-api:8000")

# Directories that are not repository surface for panel revisions.
EXCLUDED_DIRS = {".venv", "htmlcov", ".git", "scratch", "evidence-2026-10-13"}


def panel_revisions() -> list[Path]:
    return sorted(
        path for path in REPO_ROOT.glob("**/control-panel*.html")
        if not any(part in EXCLUDED_DIRS for part in path.parts)
    )


def executable_lines(text: str):
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("<!--"):
            continue
        yield stripped


def registered_routes() -> dict[tuple[str, str], object]:
    from src.main import app

    routes = {}
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods:
                routes[(method.upper(), route.path)] = route
    return routes


def panel_control_targets():
    """Yield (kind, method_or_None, target, line) for every URL-ish control."""
    text = SERVED.read_text(encoding="utf-8", errors="replace")
    patterns = [
        ("apiCall", r"apiCall\(\s*['\"]([^'\"]+)['\"](?:\s*,\s*['\"](\w+)['\"])?"),
        ("fetch", r"fetch\(\s*'(?!')([^']+\S)'"),
        ("href", r'href\s*=\s*"([^"]+)"'),
    ]
    for kind, pattern in patterns:
        for match in re.finditer(pattern, text):
            target = match.group(1).strip()
            method = "GET"
            if kind == "apiCall":
                method = (match.group(2) or "GET").upper()
            elif kind == "fetch":
                # Direct fetches often pass init with an explicit method:
                # fetch('/auth/login', { method: 'POST', ... }). Look ahead
                # within the same statement; default GET when absent.
                lookahead = text[match.start():match.start() + 400]
                m_method = re.search(r"method\s*:\s*['\"](\w+)['\"]", lookahead)
                if m_method:
                    method = m_method.group(1).upper()
            line = text[: match.start()].count("\n") + 1
            yield kind, method, target, line


def test_served_panel_is_the_only_panel_revision():
    revisions = panel_revisions()
    assert [f.name for f in revisions] == ["control-panel.html"], (
        "extra unserved panel revisions present "
        f"({[f.name for f in revisions if f.name != 'control-panel.html']}); "
        "stale revisions historically carried fabricated metrics"
    )


def test_no_fabricated_random_metrics_in_any_panel_revision():
    for revision in panel_revisions():
        for line in executable_lines(revision.read_text(encoding="utf-8", errors="replace")):
            assert "Math.random(" not in line, (
                f"{revision.name}: fabricated metric via Math.random(): {line[:120]}"
            )


def test_no_retired_or_unregistered_control_targets():
    routes = registered_routes()
    problems = []
    for kind, method, target, line in panel_control_targets():
        if kind == "href" and (target.startswith("#") or target == "/"):
            continue
        # Same-origin panel-self and observability-tool links are fine; only
        # absolute links to the closed waf-api backend host are violations.
        for host in BACKEND_HOSTS:
            if target.startswith(f"http://{host}") or target.startswith(f"https://{host}"):
                problems.append(f"L{line}: same-origin violation ({kind}): {target}")
        if target.startswith("http://") or target.startswith("https://"):
            continue
        api_path = f"/api{target}" if kind == "apiCall" else target
        path = api_path.split("?")[0]
        if path in RETIRED_TARGETS or ((method, path) not in routes):
            problems.append(f"L{line}: {kind} targets unregistered {method} {path}")
    assert not problems, "dead/invented controls in served panel:\n" + "\n".join(problems)
