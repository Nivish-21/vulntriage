# vulntriage

Rank `pip-audit` CVEs by real exploitability using an LLM.

`pip-audit` reports every vulnerability your dependencies carry — but a CVSS 9.8 in a transitive dependency you never call is not the same risk as a CVSS 5.0 in your HTTP client that handles every request. `vulntriage` feeds your CVE list, your actual dependency stack, and authoritative threat intelligence (NVD CVSS, CISA KEV, EPSS) to an LLM, which ranks them by **real reachability** rather than raw severity score.

---

## Requirements

- Python 3.11+
- `pip-audit` installed and on `PATH` (`pip install pip-audit`)
- An Anthropic API key — or credentials for OpenAI, Gemini, or a local Ollama instance

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

# Gate CI on CRITICAL only (not the default HIGH)
vulntriage scan --fail-on CRITICAL

# Save a timestamped JSON report
vulntriage scan --output-dir ./reports

# Skip all network fetches (use cached threat intel only)
vulntriage scan --offline

# Output machine-readable JSON (status messages go to stderr)
vulntriage scan --format json
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--project-root / -p` | `.` | Directory containing `requirements.txt` or `pyproject.toml` |
| `--fail-on` | `HIGH` | Exit 1 if any CVE at or above this severity: `CRITICAL / HIGH / MEDIUM / LOW / INFO` |
| `--format / -f` | `table` | Output format: `table` (Rich) or `json` (pipe-safe) |
| `--output-dir` | — | Save a timestamped JSON report to this directory after each scan |
| `--offline` | — | Skip all external API calls; use cached threat intel only |

---

### Output

```
╭─────────────────────────────────────────────────────────────╮
│             vulntriage — CVE Priority Report                 │
├───┬──────────────────────┬──────────────────┬──────┬──────┬───────┬───────────────────────────────────┬──────────────────────────────┬──────────────────────────────────╮
│ # │ CVE / PYSEC ID       │ Package          │ Risk │ CVSS │ EPSS  │ Reasoning                         │ Breaking Changes              │ Fix                              │
├───┼──────────────────────┼──────────────────┼──────┼──────┼───────┼───────────────────────────────────┼──────────────────────────────┼──────────────────────────────────┤
│ 1 │ CVE-2024-35195       │ requests 2.31.0  │ HIGH │ 9.1  │ 12.3% │ SSRF via proxied requests; direct │ verify=True is now the        │ pip install requests>=2.32.0     │
│   │ ★ CISA KEV           │ → 2.32.0         │      │      │       │ dep called at every API boundary  │ default—audit any verify=False │                                  │
├───┼──────────────────────┼──────────────────┼──────┼──────┼───────┼───────────────────────────────────┼──────────────────────────────┼──────────────────────────────────┤
│ 2 │ CVE-2022-40897       │ setuptools 65.5.0│ LOW  │ 7.5  │  0.1% │ ReDoS in package metadata parser; │ No breaking changes in patch  │ pip install setuptools>=65.5.1   │
│   │                      │ → 65.5.1         │      │      │       │ not reachable at app runtime      │ release                       │                                  │
╰───┴──────────────────────┴──────────────────┴──────┴──────┴───────┴───────────────────────────────────┴──────────────────────────────┴──────────────────────────────────╯
```

`★ CISA KEV` — CISA has confirmed this CVE is actively exploited in the wild.

---

## Threat Intelligence

Before the LLM call, `vulntriage` fetches authoritative threat data from three public feeds and injects it into the prompt:

| Feed | What it provides | Rate limit |
|---|---|---|
| [NVD REST API v2](https://nvd.nist.gov/developers/vulnerabilities) | CVSS v3.1/v3.0/v2 base score per CVE | 5 req/30s free; 50 req/30s with `NVD_API_KEY` |
| [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Whether each CVE is actively exploited in the wild | Single request, no key needed |
| [FIRST EPSS API](https://www.first.org/epss) | Exploitation probability percentage | Batch request, no key needed |

All three are cached at `~/.cache/vulntriage/` with a 24-hour TTL. The first scan pays the network cost; subsequent scans are instant.

**NVD scores are authoritative.** The NVD CVSS value always overrides whatever score the LLM returns.

### Speeding up NVD fetches

Without an NVD API key, the tool pauses 6.1 seconds between CVE lookups to stay under the public rate limit. With a key, the pause drops to 0.7 seconds — significant for projects with many CVEs.

```bash
# Get a free key at https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-key-here"
vulntriage scan
```

### Offline mode

```bash
# Skip all three feeds; use whatever is in the local cache
vulntriage scan --offline
```

Use `--offline` in air-gapped environments or when deterministic scan time matters. The scan proceeds without threat intel if the cache is empty — CVSS, KEV, and EPSS fields are simply absent from the prompt.

---

## Suppressing CVEs

Create a `.vulnignore` file in your project root to suppress CVEs your team has reviewed and accepted:

```
# Accepted — only reachable in development scripts, not at runtime
CVE-2022-40897

# Reviewed and accepted
CVE-2023-32681 Not reachable via our API surface — verified 2024-01-15
```

Lines starting with `#` are comments. Text after the CVE ID is treated as a reason and ignored by the tool. Suppressed CVEs are excluded before the LLM call and do not count toward the exit code.

---

## Provider Selection

`vulntriage` supports four LLM backends. Set `VULNTRIAGE_PROVIDER` to switch:

| Provider | Env var | Install extra | Default model |
|---|---|---|---|
| `anthropic` (default) | `ANTHROPIC_API_KEY` | — | `claude-sonnet-4-6` |
| `openai` | `OPENAI_API_KEY` | `pip install 'vulntriage[openai]'` | `gpt-4o-mini` |
| `gemini` | `GOOGLE_API_KEY` | `pip install 'vulntriage[gemini]'` | `gemini-2.0-flash` |
| `ollama` | — | `pip install 'vulntriage[ollama]'` | `llama3.2` |

```bash
# Use Gemini (free tier at aistudio.google.com/apikey)
export VULNTRIAGE_PROVIDER=gemini
export GOOGLE_API_KEY="AIza..."
vulntriage scan

# Use Ollama — fully local, no dependency data leaves your machine
export VULNTRIAGE_PROVIDER=ollama
vulntriage scan
```

**Privacy note:** All providers except Ollama send your dependency names to an external API. If your dependency list is sensitive, use `VULNTRIAGE_PROVIDER=ollama`.

### Ollama quickstart

```bash
brew install ollama
ollama pull llama3.2
pip install 'vulntriage[ollama]'
VULNTRIAGE_PROVIDER=ollama vulntriage scan
```

By default Ollama connects to `http://localhost:11434`. Override with `OLLAMA_HOST`. Use a different model with `OLLAMA_MODEL` (e.g. `OLLAMA_MODEL=mistral`). If the Ollama server is not running, `vulntriage` will start it automatically.

---

## CI Integration

`vulntriage scan` exits **1** if any CVE is ranked at or above `--fail-on` (default: `HIGH`), and **0** otherwise.

### GitHub Actions

```yaml
- name: Audit CVEs
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    NVD_API_KEY: ${{ secrets.NVD_API_KEY }}      # optional but speeds up NVD lookups
  run: |
    pip install pip-audit vulntriage
    vulntriage scan --fail-on HIGH
```

Gate on CRITICAL only:

```yaml
    vulntriage scan --fail-on CRITICAL
```

Save a report as a CI artifact:

```yaml
    vulntriage scan --output-dir ./reports --format json
```

### GitLab CI

```yaml
audit:
  script:
    - pip install pip-audit vulntriage
    - vulntriage scan --fail-on HIGH
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
    NVD_API_KEY: $NVD_API_KEY
```

---

## How it works

1. Runs `pip-audit --format json` as a subprocess
2. Reads `requirements.txt` or `pyproject.toml` to understand your actual stack
3. Loads `.vulnignore` and removes suppressed CVEs
4. Fetches threat intelligence from NVD, CISA KEV, and EPSS (skipped with `--offline`; all three cached 24h at `~/.cache/vulntriage/`)
5. Sends the enriched CVE list and stack context to the configured LLM
6. NVD CVSS overrides any score the LLM returns
7. Renders a ranked Rich table or JSON output
8. Exits 1 if any CVE is at or above `--fail-on` severity

LLM reasoning example:

> *"requests is a direct dependency called at every API boundary — HIGH (SSRF via proxied requests). setuptools is not reachable at application runtime — LOW despite CVSS 7.5."*

---

## Cost

Each scan makes one LLM API call. At `claude-sonnet-4-6` pricing (~$3/M input, $15/M output), a typical scan with 5–10 CVEs costs roughly **$0.004–0.01**. The static system prompt is cached across repeat scans (Anthropic 5-min TTL), cutting cost on subsequent runs by ~80%.

---

## Scope

- pip only (no npm, cargo, etc.)
- Context from `requirements.txt` / `pyproject.toml` — no static call-graph analysis
- Threat intel cached at `~/.cache/vulntriage/` with a 24-hour TTL

---

## Development

```bash
git clone https://github.com/Nivish-21/Vuln
cd Vuln
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
