# Quick Start Guide

## Prerequisites

- Python 3.11+
- pip
- (Optional) Docker + Docker Compose for containerized runs

---

## 1. Install

```bash
cd yula-ai-scanner/
pip install -r requirements.txt
```

If you plan to test web-based AI targets (type: `webpage`), also install the
Playwright browser:

```bash
playwright install chromium
```

---

## 2. Configure your target

Copy one of the pre-built target configs from `config/targets/` and edit it:

```bash
cp config/targets/openai_target.yaml config/targets/my_target.yaml
```

Edit `my_target.yaml` and set the `endpoint.url` and `auth` values.
API keys can be set as environment variables using `${ENV_VAR_NAME}` syntax:

```yaml
auth:
  type: api_key
  api_key: "${OPENAI_API_KEY}"
```

Then export your key:

```bash
export OPENAI_API_KEY=sk-...
```

---

## 3. Run your first scan

```bash
python run.py scan --target config/targets/my_target.yaml
```

This runs the full attack matrix (all intents × techniques × evasions) against
your target and saves a Markdown report to `output/report.md`.

### Common options

| Flag | Description |
|------|-------------|
| `--target`, `-t` | Path to your target YAML (required) |
| `--config`, `-c` | Path to scan.yaml (default: `config/scan.yaml`) |
| `--template`, `-T <id>` | Run only the template with this exact `id` (e.g. `jailbreak-dan-mode`) |
| `--folder`, `-F <name>` | Run only templates under `templates/<name>/` (e.g. `jailbreak`) |
| `--tags a,b` | Run only templates that have **all** listed tags |
| `--threshold 0.1..0.95` | Override `vulnerability_threshold` from `scan.yaml` |
| `--continue` | Resume — skip templates already tested cleanly against this target |
| `-v` | Print only vulnerable / above-safe findings + their HTTP exchange |
| `-vv` | Print every tested template (safe and vulnerable), one line each |
| `-vvv` | Print full sent prompt, full model response, and evaluation details for every test |
| `-vvvv` | Also print every HTTP request/response live, including failures and timeouts |
| `--visibility <level>` | Explicit override: `public` \| `internal` \| `confidential` \| `debug` |
| `--max-payloads 100` | Cap total payloads (fast smoke test) |
| `--output output/my_report.md` | Custom report path (`.json` sibling auto-generated) |

`--template`, `--folder`, and `--tags` combine with **AND** semantics — useful
for narrow re-runs while iterating on a specific template family.

---

## 4. Read the report

Each scan generates two report files:

- `output/report.md` — human-readable Markdown, open in any Markdown viewer
- `output/report.json` — machine-readable JSON, suitable for integrations and automation

The Markdown report contains:

- **Executive Summary**: pass rate, severity counts, scan duration
- **Findings**: each vulnerable response with score, confidence, and signals
- **Recommendations**: specific remediation steps per attack category
- **Methodology**: which attacks were tested and how many payloads

---

## 5. Run via Docker

```bash
# Build the image
docker compose build

# Run a scan
docker compose run --rm yula-ai-scanner scan \
  --target config/targets/my_target.yaml \
  -vv

# Reports appear in ./output/ on your host
```

---

## Next steps

- [Configuration Reference](configuration.md) — every option in scan.yaml and target files
- [Templates](templates.md) — write your own attack templates
- [Target Types](target_types.md) — OpenAI, Anthropic, Custom API, and Web targets
- [Authentication](authentication.md) — API keys, Bearer tokens, cookies, form login
