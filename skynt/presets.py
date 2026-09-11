"""Ready-made policies, so nobody has to write TOML before skynt is useful."""
from __future__ import annotations

import os
from pathlib import Path

DESTRUCTIVE = [
    "*delete*", "*remove*", "*drop*", "*destroy*", "*truncate*", "*purge*",
    "*wipe*", "*reset*", "*revoke*", "*kill*", "*terminate*",
]
OUTSIDE_EFFECTS = [
    "*exec*", "*shell*", "*command*", "*deploy*", "*publish*", "*send*",
    "*push*", "*merge*", "*transfer*", "*pay*", "*charge*", "*refund*",
]
READS = ["read*", "get*", "list*", "search*", "find*", "describe*", "view*", "fetch*"]

HEADER = """\
# skynt policy ({preset} preset)
#
# Every tool call your AI makes is checked against these rules, top to bottom.
# The first matching rule decides. Tool names are matched ignoring case.
#
#   allow    runs normally
#   confirm  asks you first (if your app cannot ask, the call is blocked)
#   deny     blocked, and hidden from the AI
#
# Every decision is written to the audit log. Read it with: skynt log
"""

PRESETS = {
    "balanced": ("allow", False),
    "strict": ("confirm", True),
}


def render(preset: str) -> str:
    default, allow_reads = PRESETS[preset]
    sections = [
        HEADER.format(preset=preset),
        f'default = "{default}"\naudit_log = "skynt-audit.jsonl"\n',
        _rule("Changes that destroy data or cannot be undone.", DESTRUCTIVE, "confirm"),
        _rule("Actions that run code or reach the outside world.", OUTSIDE_EFFECTS, "confirm"),
    ]
    if allow_reads:
        sections.append(_rule("Reading is safe.", READS, "allow"))
    return "\n".join(sections)


def skynt_home() -> Path:
    return Path(os.environ.get("SKYNT_HOME") or Path.home() / ".skynt")


def default_policy_path() -> Path:
    return skynt_home() / "policy.toml"


def write_policy(path: Path, preset: str, force: bool = False) -> bool:
    """Create the policy file. Returns False when it already exists and force is off."""
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(preset), encoding="utf-8")
    return True


def _rule(comment: str, patterns: list[str], action: str) -> str:
    listed = ",\n".join(f'  "{p}"' for p in patterns)
    return f"# {comment}\n[[rules]]\nmatch = [\n{listed},\n]\naction = \"{action}\"\n"
