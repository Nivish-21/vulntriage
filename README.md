# vulntriage

Rank `pip-audit` CVEs by real exploitability using an LLM.

`pip-audit` reports every vulnerability your dependencies carry — but a CVSS 9.8 in a transitive dependency you never call is not the same risk as a CVSS 5.0 in your HTTP client that handles every request. `vulntriage` feeds your CVE list, your actual dependency stack, and authoritative threat intelligence (NVD CVSS, CISA KEV, EPSS) to an LLM, which ranks them by **real reachability** rather than raw severity score.

> ### 💸 No API key? Use the AI subscription you already pay for.
>
> If you have **Claude Code**, **OpenAI Codex**, or the **Gemini CLI** installed and logged in, vulntriage can drive it directly — no API key, no metered billing, no extra cost. You get the **same cloud-grade ranking** as the paid API, billed against your existing subscription:
>
> ```bash
> vulntriage scan --provider claude-cli   # or: codex-cli / gemini-cli
> ```
>
> Nothing to configure — vulntriage runs the CLI for you. [Setup details below.](#no-api-key-use-your-coding-cli-subscription)

---

## Requirements

- Python 3.11+
- `pip-audit` installed and on `PATH` (`pip install pip-audit`)
- An LLM backend — any one of: an Anthropic/OpenAI/Gemini API key; a logged-in coding CLI (`claude`, `codex`, or `gemini`) on your existing subscription, no API key needed; or a local Ollama instance

---

## Installation

```bash
pip install vulntriage
```

---

## Usage

```bash
# Option A — no API key: use a coding CLI you're already logged into
vulntriage scan --provider claude-cli      # or codex-cli / gemini-cli

# Option B — API key
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
| `--provider` | `anthropic` | LLM backend. API key: `anthropic / openai / gemini`. Subscription CLI (no key): `claude-cli / codex-cli / gemini-cli`. Local: `ollama` |
| `--model` | provider default | Model name to use (e.g. `phi4-mini`, `gpt-4o-mini`) |
| `--fail-on` | `none` | Exit 1 if any CVE at or above this severity: `CRITICAL / HIGH / MEDIUM / LOW / INFO / none` |
| `--format / -f` | `table` | Output format: `table` (Rich), `json`, or `sarif` |
| `--output-dir` | — | Save a timestamped JSON report to this directory after each scan |
| `--offline` | — | Skip all external API calls; use cached threat intel only |
| `--no-cache` | — | Bypass the 24-hour threat-intel cache and re-fetch from NVD/KEV/EPSS |
| `--batch-size` | `10` | Max CVEs per LLM call (reduce to ≤10 for local models with small context windows) |
| `--airgap` | — | Fully air-gapped mode: skip pip-audit network calls and all threat intel fetches |

---

### Output

Findings are printed as priority-ordered cards — each tells you what to fix, why it matters, the exact version to upgrade to, and what might break:

```
vulntriage — CVE Priority Report   (2 findings, highest priority first)

#1  HIGH  requests 2.31.0  ★ CISA KEV ───────────────────────────────────
CVE        CVE-2024-35195
Why        Attack: SSRF via proxied requests. Path: app.py:52 requests.get()
           on the request boundary. Verdict: REACHABLE — called every request.
Fix        pip install "requests>=2.32.0"   (you have 2.31.0 → need ≥ 2.32.0)
Breaking   verify=True is now the default — audit any verify=False call sites.
Code       app.py:52 requests.get(verify=, timeout=)
Severity   CVSS 9.1 · EPSS 12.3% · ★ exploited in the wild (CISA KEV)

#2  LOW  jinja2 3.1.0 ───────────────────────────────────────────────────
CVE        CVE-2024-22195
Why        Attack: XSS via xmlattr filter. Path: no call site listed —
           filter not used in source. Verdict: UNLIKELY.
Fix        pip install "jinja2>=3.1.3"   (you have 3.1.0 → need ≥ 3.1.3)
Breaking   Safe, backwards-compatible patch release.
```

`★ CISA KEV` — CISA has confirmed this CVE is actively exploited in the wild. `Code` and `Severity` lines appear only when there is something to show. For machine-readable output use `--format json` or `--format sarif`.

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

`vulntriage` supports three kinds of LLM backend. Use `--provider` to switch.

**API-key providers** — metered pay-per-token billing:

| Provider | API key env var | Install extra | Default model |
|---|---|---|---|
| `anthropic` (default) | `ANTHROPIC_API_KEY` | — | `claude-sonnet-4-6` |
| `openai` | `OPENAI_API_KEY` | `pip install 'vulntriage[openai]'` | `gpt-4o-mini` |
| `gemini` | `GOOGLE_API_KEY` | `pip install 'vulntriage[gemini]'` | `gemini-2.0-flash` |

**Subscription-CLI providers** — no API key; uses an AI coding CLI you are already logged into (see below):

| Provider | Requires | Cost |
|---|---|---|
| `claude-cli` | `claude` (Claude Code) installed + logged in | your Claude subscription |
| `codex-cli` | `codex` (OpenAI Codex CLI) installed + logged in | your ChatGPT/Codex subscription |
| `gemini-cli` | `gemini` (Google Gemini CLI) installed + logged in | your Gemini subscription |

**Local provider** — fully offline, no data leaves your machine:

| Provider | Install extra | Default model |
|---|---|---|
| `ollama` | `pip install 'vulntriage[ollama]'` | `llama3.2` |

```bash
# Use Gemini API (free tier at aistudio.google.com/apikey)
export GOOGLE_API_KEY="AIza..."
vulntriage scan --provider gemini

# Use Ollama — fully local, no dependency data leaves your machine
vulntriage scan --provider ollama --model phi4-mini
```

### No API key? Use your coding-CLI subscription

If you pay for Claude Code, OpenAI Codex, or the Gemini CLI but have no separate
API key, `vulntriage` can borrow the subscription you are already logged into.
There is **nothing to configure in vulntriage** — it spawns the CLI as a
subprocess (exactly like it spawns `pip-audit`) and reads back the ranking. The
credentials live in the CLI's own config; `vulntriage` never sees a key.

One-time setup — install and log into whichever CLI you have:

```bash
# Claude Code
npm i -g @anthropic-ai/claude-code   # then run `claude` once to log in
vulntriage scan --provider claude-cli

# OpenAI Codex
npm i -g @openai/codex && codex login
vulntriage scan --provider codex-cli

# Google Gemini CLI
npm i -g @google/gemini-cli          # then run `gemini` once to log in
vulntriage scan --provider gemini-cli
```

Notes:
- Each CLI runs **read-only** with tool use disabled — it only ranks the CVE list.
- First run is slower than a raw API call (agentic CLIs have heavier startup); the per-provider timeout defaults to 180s and is overridable via `VULNTRIAGE_CLAUDE_CLI_TIMEOUT` / `VULNTRIAGE_CODEX_CLI_TIMEOUT` / `VULNTRIAGE_GEMINI_CLI_TIMEOUT`.
- Output quality matches the underlying model (Sonnet/GPT/Gemini), so this is a far better free option than local Ollama models for reachability judgements.
- Bound to your local login — best for local/dev use, not shared CI runners (use the API-key providers for unattended CI).
- If the CLI is missing or not logged in, `vulntriage` fails with a clear message; it never hangs or silently degrades.

**Privacy note:** Every provider except `ollama` sends your dependency names off the machine — the API providers to their REST API, the subscription-CLI providers via the coding CLI's own session. If your dependency list is sensitive, use `--provider ollama`.

### Ollama quickstart

```bash
brew install ollama
ollama pull llama3.2
pip install 'vulntriage[ollama]'
vulntriage scan --provider ollama
```

By default Ollama connects to `http://localhost:11434`. Override with `OLLAMA_HOST`. If the Ollama server is not running, `vulntriage` will start it automatically.

---

## CI Integration

`vulntriage scan` exits **1** if any CVE is ranked at or above `--fail-on` (default: `none`, meaning the scan always exits 0 unless you set a threshold), and **0** otherwise.

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
