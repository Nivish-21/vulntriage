# AGENTS.md

Instructions for coding agents (Codex, Claude Code, etc.) working in this
repository. Humans: see `README.md` instead.

## What this repo is

vulntriage — zero-config CVE triage for Python. Wraps `pip-audit`, enriches
the result with NVD/CISA KEV/EPSS, ranks it with an LLM (API key, local
Ollama, or your already-logged-in coding CLI subscription), and hands back a
short, priority-ordered fix list instead of a wall of raw severities.

## Source of truth

The running code and its tests are the source of truth — `README.md` for
behaviour and usage, `src/vulntriage/` and `tests/` for exact contracts.

## Active plan

`docs/plan.md` has a fully scoped, not-yet-started plan: adding npm/Node
ecosystem support (currently Python-only via `pip-audit`). It was written
after tracing this repo's actual source (not guessed from the README) while
comparing it against a real, separate finding in another project — read it
before starting any npm-related work, it names exact files, exact current
code, and exactly which pieces are confirmed vs. still need a design
decision during implementation. Don't start building a Python-ecosystem
feature without checking `docs/plan.md` first either, in case it's already
mid-flight.

## Commands

```sh
uv sync            # or: pip install -e .
pytest              # test suite
```

Check `pyproject.toml` for the exact configured lint/format tooling before
assuming a command that isn't listed here.

## Conventions

- Python 3.11+, type-hinted, dataclasses for models (see `models.py`).
- Subprocess calls use `subprocess.run` with an argv list, not a shell
  string — same convention as MigrateProof (a sibling project by the same
  author), keep it consistent.
- `ranker.py`'s `_FIX_CMD_RE` allowlist is a real safety guard on LLM
  output, not incidental — any new fix-command allowlist (e.g. for npm)
  needs the same "validate the LLM's own text before it goes anywhere"
  treatment, not a looser one.
