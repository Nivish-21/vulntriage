# vulntriage

Rank `pip-audit` CVEs by real exploitability using Claude AI.

`pip-audit` reports every vulnerability your dependencies carry — but a CVSS 9.8 in a transitive dependency you never call is not the same as a CVSS 5.0 in your HTTP client that handles every request. `vulntriage` feeds your CVE list and your actual dependency stack to Claude, which ranks them by **real reachability** rather than raw severity score.

---

## Requirements

- Python 3.11+
- `pip-audit` installed and on `PATH` (`pip install pip-audit`)
- An Anthropic API key (get one at [console.anthropic.com](https://console.anthropic.com))

---

## Installation

```bash
pip install vulntriage
```

---

## Usage

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

# Scan the current directory (needs requirements.txt or pyproject.toml)
vulntriage scan

# Scan a specific project
vulntriage scan --project-root /path/to/project
```

### Output

```
╭──────────────────────────────────────────────────────────────╮
│             vulntriage — CVE Priority Report                  │
├───┬──────────────────┬──────────────────┬──────┬─────────────┤
│ # │ CVE / PYSEC ID   │ Package          │ Risk │ Fix         │
├───┼──────────────────┼──────────────────┼──────┼─────────────┤
│ 1 │ CVE-2023-32681   │ requests 2.28.0  │ HIGH │ pip install │
│   │                  │                  │      │ requests==  │
│   │                  │                  │      │ 2.31.0      │
╰───┴──────────────────┴──────────────────┴──────┴─────────────╯
```

---

## CI Integration

`vulntriage scan` exits **1** if any CVE is ranked `HIGH` or `CRITICAL`, and **0** otherwise.

### GitHub Actions

```yaml
- name: Audit CVEs
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    pip install pip-audit vulntriage
    vulntriage scan
```

### GitLab CI

```yaml
audit:
  script:
    - pip install pip-audit vulntriage
    - vulntriage scan
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
```

---

## How it works

1. Runs `pip-audit --format json` as a subprocess
2. Reads `requirements.txt` or `pyproject.toml` to understand your actual stack
3. Sends both to Claude with a prompt that emphasises **reachability over CVSS**
4. Renders a ranked table via Rich
5. Exits 1 if any HIGH or CRITICAL finding — zero otherwise

Claude reasoning example:

> *"requests is a direct dependency called at every API boundary — HIGH. certifi is transitive, never imported by your code — LOW despite CVSS 8.8."*

---

## Cost

Each scan makes one Claude API call. At current `claude-sonnet-4-6` pricing, a typical scan with 5–10 CVEs costs roughly **$0.03–0.08**.

---

## Scope (v1)

- pip only (no npm, cargo, etc.)
- Context from `requirements.txt` / `pyproject.toml` — no static call-graph analysis
- No caching between scans

---

## Development

```bash
# Clone and set up
git clone https://github.com/your-org/vulntriage
cd vulntriage
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Lint + format
black . && ruff check .
```

---

## License

MIT
