"""Report rendering (terminal/json/md) and the CLI surface (flags, exit codes)."""

from __future__ import annotations

import json

from agent_blast_radius.classify import analyze
from agent_blast_radius.cli import main
from agent_blast_radius.parser import parse_transcript
from agent_blast_radius.report import render_json, render_markdown, render_terminal


def _report(path):
    return analyze(parse_transcript(path))


# --- rendering -----------------------------------------------------------

def test_terminal_shows_tier_and_headline(critical_transcript):
    text = render_terminal(_report(critical_transcript), color=False)
    assert "BLAST TIER" in text
    assert "CRITICAL" in text
    assert "IRREVERSIBLE & SUCCEEDED" in text


def test_terminal_no_color_has_no_ansi(benign_transcript):
    text = render_terminal(_report(benign_transcript), color=False)
    assert "\x1b[" not in text


def test_json_is_valid_and_complete(destructive_transcript):
    data = json.loads(render_json(_report(destructive_transcript)))
    assert data["tier"] == "wide"
    assert "actions" in data and data["actions"]
    assert "headlines" in data
    assert any(a["category"] == "vcs" for a in data["actions"])


def test_markdown_has_sections(critical_transcript):
    md = render_markdown(_report(critical_transcript))
    assert "# agent-blast-radius report" in md
    assert "Irreversible & succeeded" in md


# --- cli -----------------------------------------------------------------

def test_cli_report_runs(benign_transcript, capsys):
    rc = main(["report", benign_transcript, "--no-color"])
    assert rc == 0
    assert "CONTAINED" in capsys.readouterr().out


def test_cli_json_flag(destructive_transcript, capsys):
    rc = main(["report", destructive_transcript, "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tier"] == "wide"


def test_cli_fail_on_critical_exits_1(critical_transcript, capsys):
    rc = main(["report", critical_transcript, "--no-color", "--fail-on-critical"])
    capsys.readouterr()
    assert rc == 1


def test_cli_fail_on_critical_passes_when_clean(benign_transcript, capsys):
    rc = main(["report", benign_transcript, "--no-color", "--fail-on-critical"])
    capsys.readouterr()
    assert rc == 0


def test_cli_only_filter(destructive_transcript, capsys):
    rc = main(["report", destructive_transcript, "--no-color", "--only", "vcs"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERSION CONTROL" in out
    # SYSTEM section (the rm -rf) should be filtered out of the view.
    assert "SYSTEM / DESTRUCTIVE" not in out


def test_cli_only_filter_json(destructive_transcript, capsys):
    rc = main(["report", destructive_transcript, "--json", "--only", "vcs"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert all(a["category"] == "vcs" for a in data["actions"])


def test_cli_danger_min_filter(critical_transcript, capsys):
    rc = main(["report", critical_transcript, "--json", "--danger-min", "high"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["actions"]
    assert all(a["severity"] in ("high", "critical") for a in data["actions"])


def test_cli_filter_does_not_change_gate(critical_transcript, capsys):
    """Filtering the view to 'files' must still let --fail-on-critical fire on
    the force-push that's no longer shown."""
    rc = main(["report", critical_transcript, "--no-color",
               "--only", "files", "--fail-on-critical"])
    capsys.readouterr()
    assert rc == 1


def test_cli_md_writes_file(benign_transcript, tmp_path, capsys):
    out_md = tmp_path / "out.md"
    rc = main(["report", benign_transcript, "--no-color", "--md", str(out_md)])
    capsys.readouterr()
    assert rc == 0
    assert out_md.exists()
    assert "agent-blast-radius report" in out_md.read_text(encoding="utf-8")


def test_cli_missing_target_exits_2(capsys):
    rc = main(["report", "definitely-not-a-real-target-xyz"])
    capsys.readouterr()
    assert rc == 2


def test_cli_version(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "blast-radius" in capsys.readouterr().out


# --- untrusted transcript text: terminal control characters ----------------
# The transcript is written from the actions of the agent under review, so a
# command, path, URL, query, slug or cwd can carry ESC / BEL / C1 / bidi
# characters that rewrite the terminal when the report is printed.

_ESC = "\x1b"
_BEL = "\x07"
_CONTROL = frozenset(
    [chr(c) for c in range(0x00, 0x20) if chr(c) not in "\n\t"]
    + [chr(c) for c in range(0x7f, 0xa0)]
    + ["\u061c", "\u200e", "\u200f"]
    + [chr(c) for c in range(0x202a, 0x202f)]
    + [chr(c) for c in range(0x2066, 0x206a)]
)


def _control_chars(text):
    return sorted({hex(ord(ch)) for ch in text if ch in _CONTROL})


def _hostile_transcript(tmp_path):
    from tests.conftest import assistant_tool, bash, tool_result, write_jsonl
    records = [
        bash("t1", "git push --force origin main #" + _ESC + "[99A" + _ESC
             + "[JBLAST TIER CONTAINED none"),
        tool_result("t1", "+ abc...def main -> main (forced update)"),
        assistant_tool("t2", "WebSearch",
                       {"query": _ESC + "]52;c;ZWNobyBwd25lZA==" + _BEL}),
        tool_result("t2", "search failed", is_error=True),
        assistant_tool("t3", "Write", {
            "file_path": "C:\\fake\\project\\x.py" + _ESC + "[8m", "content": "x"}),
        tool_result("t3", "File created"),
        bash("t4", "git " + _ESC + "[2Jstatus"),  # detail becomes "git <token>"
        tool_result("t4", "ok"),
        bash("t5", "rm -f 'notes\u202etxt.exe'"),
        tool_result("t5", ""),
    ]
    records[0]["cwd"] = "C:\\fake\\project" + _ESC + "[2J\x9b2J"
    records[0]["slug"] = "demo" + _ESC + "]0;pwned" + _BEL
    return write_jsonl(tmp_path / "hostile.jsonl", records)


def test_terminal_escapes_control_chars_from_transcript(tmp_path):
    report = _report(_hostile_transcript(tmp_path))
    text = render_terminal(report, color=False)
    assert _control_chars(text) == []
    # Shown as visible text, so the injection attempt itself is evidence.
    assert "\\x1b[99A" in text
    assert "git push --force origin main" in text
    assert "CRITICAL" in text


def test_terminal_color_mode_only_emits_own_styles(tmp_path):
    import re
    report = _report(_hostile_transcript(tmp_path))
    text = render_terminal(report, color=True)
    own_sgr_removed = re.sub(r"\x1b\[[0-9;]*m", "", text)
    assert _control_chars(own_sgr_removed) == []


def test_markdown_escapes_control_chars_from_transcript(tmp_path):
    md = render_markdown(_report(_hostile_transcript(tmp_path)))
    assert _control_chars(md) == []
    assert "\\x1b]52;c;" in md


def test_cli_report_escapes_control_chars(tmp_path, capsys):
    path = _hostile_transcript(tmp_path)
    out_md = tmp_path / "hostile.md"
    rc = main(["report", path, "--no-color", "--md", str(out_md)])
    out = capsys.readouterr().out
    assert rc == 0
    assert _control_chars(out) == []
    assert _control_chars(out_md.read_text(encoding="utf-8")) == []


# --- credentials inside agent commands -----------------------------------
# The --md and --json reports are the artifacts people paste into a ticket
# during an incident, so secret-shaped values are masked in every rendering.

_SECRETS = {
    "gh_pat": "ghp_AAAABBBBCCCCDDDDEEEEFFFF1234567890ab",
    "pg_pw": "S3cretPassw0rd",
    "sk": "sk-proj-Zx81kd0QmW3nTq9LpR5vY2hBc7",
    "mysql_pw": "HunterTwo!2026",
    "slack": "xoxb-2931-8812-Qk2mZp0aLx9vT",
    "aws_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "google_key": "AIzaSyD4exampleexampleexample1234567",
    "curl_user": "Pa55w0rd-9921",
}


def _creds_transcript(tmp_path):
    from tests.conftest import bash, tool_result, write_jsonl
    s = _SECRETS
    commands = [
        f"git push https://x-access-token:{s['gh_pat']}@github.com/acme/api.git main",
        f"psql postgresql://admin:{s['pg_pw']}@db.internal/prod -c 'DELETE FROM sessions'",
        "curl -s -X POST https://api.openai.com/v1/files "
        f"-H 'Authorization: Bearer {s['sk']}' --data @x.json",
        f"mysql -u root -p{s['mysql_pw']} -h db1 -e 'DROP TABLE tmp_import'",
        f"curl -X POST -H \"Authorization: Bearer {s['slack']}\" "
        "https://slack.com/api/chat.postMessage -d text=hi",
        f"docker run -e AWS_ACCESS_KEY_ID={s['aws_id']} "
        f"-e AWS_SECRET_ACCESS_KEY={s['aws_secret']} app",
        "curl https://maps.googleapis.com/maps/api/geocode/json"
        f"?address=x&key={s['google_key']}",
        f"curl -u admin:{s['curl_user']} -X DELETE http://localhost:9200/logs",
    ]
    records = []
    for i, cmd in enumerate(commands):
        records += [bash(f"c{i}", cmd), tool_result(f"c{i}", "ok")]
    return write_jsonl(tmp_path / "creds.jsonl", records)


def _leaks(text):
    return sorted(name for name, secret in _SECRETS.items() if secret in text)


def test_markdown_redacts_credentials(tmp_path):
    md = render_markdown(_report(_creds_transcript(tmp_path)))
    assert _leaks(md) == []
    # The command stays recognisable.
    assert "git push https://x-access-token:***@github.com/acme/api.git main" in md
    assert "psql postgresql://admin:***@db.internal/prod" in md
    assert "Authorization: Bearer ***" in md
    assert "mysql -u root -p*** -h db1" in md


def test_json_redacts_credentials(tmp_path):
    data = json.loads(render_json(_report(_creds_transcript(tmp_path))))
    blob = json.dumps(data)
    assert _leaks(blob) == []
    targets = [a["target"] for a in data["actions"]]
    assert "curl -u admin:*** -X DELETE http://localhost:9200/logs" in targets
    assert any("AWS_SECRET_ACCESS_KEY=***" in t for t in targets)
    assert any("&key=***" in t for t in targets)


def test_terminal_redacts_credentials(tmp_path):
    text = render_terminal(_report(_creds_transcript(tmp_path)), color=False)
    assert _leaks(text) == []


def test_cli_md_and_json_redact_credentials(tmp_path, capsys):
    path = _creds_transcript(tmp_path)
    out_md = tmp_path / "creds.md"
    main(["report", path, "--json", "--md", str(out_md)])
    out = capsys.readouterr().out
    assert _leaks(out) == []
    assert _leaks(out_md.read_text(encoding="utf-8")) == []


def test_redaction_keeps_the_verdict(tmp_path):
    """Masking happens at render time only; classification still sees the
    real command, so the tier and headlines do not move."""
    report = _report(_creds_transcript(tmp_path))
    assert report.tier.value == "critical"
    assert len(report.headlines()) == 5


def test_redaction_leaves_ordinary_commands_alone(critical_transcript,
                                                  destructive_transcript):
    for path in (critical_transcript, destructive_transcript):
        report = _report(path)
        data = json.loads(render_json(report))
        assert [a["target"] for a in data["actions"]] == \
            [a.target for a in report.actions]
        assert [a["raw"] for a in data["actions"]] == [a.raw for a in report.actions]
