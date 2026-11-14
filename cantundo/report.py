"""Render a BlastReport: ANSI terminal report, Markdown, or JSON.

The terminal report leads with the headline, the irreversible-and-succeeded
actions, because in an incident those are the only things you can't fix by
re-running the agent. Everything below is grouped by category for context.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from .models import (
    Action,
    BlastReport,
    BlastTier,
    Category,
    FileOp,
    Reversibility,
    Severity,
)

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_RED = "\x1b[31m"
_CYAN = "\x1b[36m"
_MAGENTA = "\x1b[35m"

_TIER_STYLE = {
    BlastTier.CONTAINED: (_GREEN, "CONTAINED"),
    BlastTier.MODERATE: (_YELLOW, "MODERATE"),
    BlastTier.WIDE: (_RED, "WIDE"),
    BlastTier.CRITICAL: (_RED, "CRITICAL"),
}

_SEVERITY_STYLE = {
    Severity.CRITICAL: (_RED, "CRIT"),
    Severity.HIGH: (_RED, "HIGH"),
    Severity.MEDIUM: (_YELLOW, "MED"),
    Severity.LOW: (_DIM, "LOW"),
    Severity.INFO: (_DIM, "INFO"),
}

_REV_LABEL = {
    Reversibility.REVERSIBLE: "reversible",
    Reversibility.HARD_TO_REVERSE: "hard-to-reverse",
    Reversibility.IRREVERSIBLE: "IRREVERSIBLE",
}

_CATEGORY_LABEL = {
    Category.FILES: "Files",
    Category.VCS: "Version control",
    Category.NETWORK: "Network / external",
    Category.PACKAGES: "Packages / env",
    Category.SYSTEM: "System / destructive",
    Category.SECRETS: "Secrets surface",
}

_FILEOP_LABEL = {
    FileOp.CREATED: "created",
    FileOp.MODIFIED: "modified",
    FileOp.DELETED: "deleted",
    FileOp.MOVED: "moved",
}


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, *styles: str, enabled: bool = True) -> str:
    if not enabled or not styles:
        return text
    return "".join(styles) + text + _RESET


# --- untrusted text ------------------------------------------------------
# Commands, paths, URLs, queries, the slug and the cwd all come from the
# transcript, which the agent under review wrote. Before any of it is shown:
#
# _safe turns terminal control characters (C0 except newline and tab, DEL,
# C1) and bidi overrides into visible \xNN / \uNNNN text, so an ESC or OSC
# sequence cannot move the cursor, erase the report or set the clipboard.
#
# _redact masks secret-shaped values (URL passwords, Authorization / Bearer
# values, token= / key= / password=, known token prefixes) as ***. The
# Markdown and JSON reports get pasted into tickets during an incident. The
# command stays recognisable and the event index still points at the
# original line; classification ran on the real text, so verdicts don't move.

_CONTROL_RE = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _escape_control(match: re.Match) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def _safe(text: str) -> str:
    return _CONTROL_RE.sub(_escape_control, text)


_REDACTIONS = [
    # scheme://user:password@host -> scheme://user:***@host
    (re.compile(r"(://[^/@\s:]*:)[^/\s]+@"), r"\1***@"),
    # Authorization: Bearer <value>, and API key headers
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:(?:bearer|basic|token|bot|digest)\s+)?)"
                r"[^\s'\"]+"), r"\1***"),
    (re.compile(r"(?i)\b((?:x-api-key|api-key|x-auth-token|private-token)\s*:\s*)"
                r"[^\s'\"]+"), r"\1***"),
    # Bearer <token> outside a header (token-like values only, not prose)
    (re.compile(r"(?i)\b(bearer\s+)(?=[\w.~+/=-]*\d)[\w.~+/=-]{8,}"), r"\1***"),
    # password=, token=, secret=, key= (AWS_SECRET_ACCESS_KEY=, ?key=, ...)
    (re.compile(r"(?i)(?<![a-z0-9])((?:password|passwd|pass|token|secret|"
                r"api[_-]?key|apikey|key)=['\"]?)[^\s&'\"]+"), r"\1***"),
    # well-known token shapes
    (re.compile(r"(?<![A-Za-z0-9])(gh[pousr]_|github_pat_|glpat-|sk-|sk_live_|"
                r"sk_test_|rk_live_|xox[abprs]-|AIza)[\w-]{16,}"), r"\1***"),
    (re.compile(r"(?<![A-Za-z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Za-z])"), r"\1***"),
]

# mysql -p<password> and curl -u user:<password>: other tools reuse these flag
# shapes (docker -u uid:gid), so they are masked only next to that client.
_MYSQL_RE = re.compile(r"(?i)\b(?:mysql|mysqldump|mysqladmin|mariadb)\b")
_MYSQL_PW_RE = re.compile(r"(?<!\S)(-p['\"]?)[^\s'\"]+")
_CURL_RE = re.compile(r"(?i)\bcurl\b")
_CURL_USER_RE = re.compile(r"(?<!\S)((?:-u|--user)(?:=|\s+)?['\"]?[^\s:'\"]*:)[^\s'\"]+")


def _redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    if _MYSQL_RE.search(text):
        text = _MYSQL_PW_RE.sub(r"\1***", text)
    if _CURL_RE.search(text):
        text = _CURL_USER_RE.sub(r"\1***", text)
    return text


def _short(text: str, width: int = 88) -> str:
    text = _safe(" ".join(text.split()))
    return text if len(text) <= width else text[: width - 1] + "…"


def render_terminal(report: BlastReport, color: bool | None = None) -> str:
    color = _colors_enabled() if color is None else color
    session = report.session
    lines: list[str] = []
    out = lines.append

    title = session.slug or Path(session.path).stem[:12]
    out("")
    out(_paint("  cantundo", _BOLD, _CYAN, enabled=color)
        + _paint(": what did this agent touch, and what's irreversible?",
                 _DIM, enabled=color))
    out(_paint(f"  session {_safe(title)} · {len(session.events)} events"
               + (f" · {_safe(session.cwd)}" if session.cwd else ""),
               _DIM, enabled=color))
    out("")

    tier_style, tier_label = _TIER_STYLE[report.tier]
    out(f"  {_paint('BLAST TIER', _BOLD, enabled=color)}  "
        + _paint(tier_label, _BOLD, tier_style, enabled=color))
    counts = report.counts()
    summary = " · ".join(f"{counts[c.value]} {c.value}" for c in Category
                         if counts[c.value])
    out(_paint("  " + (summary or "no side-effecting actions detected"),
               _DIM, enabled=color))
    out("")

    headlines = report.headlines()
    out(_paint("  IRREVERSIBLE & SUCCEEDED", _BOLD,
               _RED if headlines else _DIM, enabled=color)
        + _paint(f"  ({len(headlines)})", _DIM, enabled=color))
    if headlines:
        for action in headlines:
            sev_style, sev_label = _SEVERITY_STYLE[action.severity]
            out(f"  {_paint('● ' + sev_label.ljust(4), sev_style, _BOLD, enabled=color)}"
                f" {_short(_redact(action.target))}")
            out(_paint(f"    └─ {_safe(action.detail)}  [event {action.event_index}]",
                       _DIM, enabled=color))
    else:
        out(_paint("  none: nothing the agent did is unrecoverable.",
                   _DIM, enabled=color))
    out("")

    grouped = report.by_category()
    for category in Category:
        items = grouped[category]
        if not items:
            continue
        out(_paint(f"  {_CATEGORY_LABEL[category].upper()}", _BOLD, enabled=color)
            + _paint(f"  ({len(items)})", _DIM, enabled=color))
        for action in items:
            out("  " + _format_action_line(action, color))
        out("")

    return "\n".join(lines)


def _format_action_line(action: Action, color: bool) -> str:
    sev_style, sev_label = _SEVERITY_STYLE[action.severity]
    mark = "✓" if action.succeeded else "✗"
    mark_style = _GREEN if action.succeeded else _RED
    op = ""
    if action.file_op is not None:
        op = _paint(f"[{_FILEOP_LABEL[action.file_op]}", _DIM, enabled=color)
        if action.edit_count > 1 and action.file_op is FileOp.MODIFIED:
            op += _paint(f" ×{action.edit_count}", _DIM, enabled=color)
        op += _paint("] ", _DIM, enabled=color)
    rev = _paint(_REV_LABEL[action.reversibility],
                 _MAGENTA if action.reversibility is Reversibility.IRREVERSIBLE else _DIM,
                 enabled=color)
    escape = _paint(" ⚠path-escape", _RED, enabled=color) if action.path_escape else ""
    return (f"{_paint(mark, mark_style, enabled=color)} "
            f"{_paint(sev_label.ljust(4), sev_style, enabled=color)} "
            f"{op}{_short(_redact(action.target), 70)}  "
            f"{rev}{escape}")


# --- JSON ----------------------------------------------------------------

def _action_dict(action: Action) -> dict:
    return {
        "category": action.category.value,
        "target": _redact(action.target),
        "raw": _redact(action.raw),
        "event_index": action.event_index,
        "reversibility": action.reversibility.value,
        "severity": action.severity.value,
        "succeeded": action.succeeded,
        "detail": action.detail,
        "file_op": action.file_op.value if action.file_op else None,
        "edit_count": action.edit_count,
        "path_escape": action.path_escape,
        "headline": action.is_headline(),
    }


def render_json(report: BlastReport) -> str:
    return json.dumps({
        "transcript": report.session.path,
        "session_id": report.session.session_id,
        "cwd": report.session.cwd,
        "tier": report.tier.value,
        "counts": report.counts(),
        "headlines": [_action_dict(a) for a in report.headlines()],
        "actions": [_action_dict(a) for a in report.actions],
    }, indent=2)


# --- Markdown ------------------------------------------------------------

def render_markdown(report: BlastReport) -> str:
    session = report.session
    lines = [
        "# cantundo report",
        "",
        f"- **Transcript:** `{_safe(Path(session.path).name)}`",
        f"- **Project:** `{_safe(session.cwd or 'unknown')}`",
        f"- **Blast tier:** {report.tier.value.upper()}",
        "",
        "## Irreversible & succeeded",
        "",
    ]
    headlines = report.headlines()
    if headlines:
        lines += ["| Severity | Action | Why | Event |", "|---|---|---|---|"]
        for a in headlines:
            lines.append(
                f"| {a.severity.value.upper()} | `{_md(_redact(a.target))}` "
                f"| {_md(a.detail)} | {a.event_index} |")
    else:
        lines.append("_None: nothing the agent did is unrecoverable._")
    lines.append("")

    grouped = report.by_category()
    for category in Category:
        items = grouped[category]
        if not items:
            continue
        lines += [f"## {_CATEGORY_LABEL[category]}", "",
                  "| ✓ | Severity | Target | Reversibility | Why | Event |",
                  "|---|---|---|---|---|---|"]
        for a in items:
            mark = "✓" if a.succeeded else "✗"
            lines.append(
                f"| {mark} | {a.severity.value.upper()} | `{_md(_redact(a.target))}` "
                f"| {a.reversibility.value} | {_md(a.detail)} | {a.event_index} |")
        lines.append("")
    return "\n".join(lines)


def _md(text: str) -> str:
    return _short(text, 120).replace("|", "\\|").replace("`", "'")
