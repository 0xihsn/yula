# Configuration Reference

YULA AI Scanner uses two YAML configuration files:

- **`config/scan.yaml`** — controls the scan itself (taxonomy paths, visibility, rate limits, output)
- **`config/targets/*.yaml`** — defines the AI system to test (URL, auth, model settings)

---

## scan.yaml

The full Pydantic schema lives in
[yula_ai_scanner/config/scan_schema.py](../yula_ai_scanner/config/scan_schema.py).
Every field has a default — the smallest valid `scan.yaml` is empty.

```yaml
# ── Scan runtime settings ────────────────────────────────────────────────────
scan:
  visibility: internal        # public | internal | confidential | debug
  max_payloads: null          # null = no cap; integer limits total payloads
  concurrency: 5              # concurrent requests in flight (1..50; auto-clamped to 1 for webpage targets)
  requests_per_minute: 60     # token-bucket rate limit (1..1000)
  timeout_seconds: 30         # per-request HTTP timeout (5..300)
  max_retries: 3              # retries on transient errors (0..10)
  vulnerability_threshold: 0.5  # confidence threshold for vulnerable verdict (0.1..0.95)
  signals_blend: 0.5          # 0.0 = template matchers only; 1.0 = full global signal weight

# ── Output ────────────────────────────────────────────────────────────────────
output:
  report_path: "output/report.md"
  log_file: "output/yula-ai-scanner.log"   # null to disable file logging
  log_level: INFO                          # DEBUG | INFO | WARNING | ERROR | CRITICAL
```

> **Where did `taxonomy:` and `attacks:` go?** Earlier YULA versions exposed
> taxonomy and intent/technique/evasion selection here. Today, **attack templates
> are loaded directly from `templates/`** — every `*.yaml` file is loaded
> recursively, no enumeration in `scan.yaml` is needed. Filter at run time with
> `--template`, `--folder`, or `--tags` instead.

### Visibility Levels

| Level | CLI shortcut | What's streamed per test in the UI | What's in the report |
|-------|--------------|------------------------------------|---------------------|
| `public` | `-v` | Template name **only when vulnerable** (or any finding above SAFE) | Summary + severity counts only |
| `internal` | `-vv` | One line per tested template (safe **and** vulnerable) | + Matched signals + recommendations |
| `confidential` | *(none)* | Same as `internal`, with full payload + response | + Full payloads + AI responses |
| `debug` | `-vvv` / `-vvvv` | Full sent prompt + full model response + evaluation block (status, confidence, matched signals, intent/technique/evasion, HTTP status, duration). With `-vvvv` every HTTP exchange is printed, including failures. | Same content as `confidential` |

The `-v` flag on `scan` is a repeatable count that overrides `scan.visibility` from
`scan.yaml`. The explicit `--visibility <level>` flag still works and takes precedence
over `-v` when both are supplied.

### Detection threshold and signal blend

- `vulnerability_threshold` (default `0.5`): minimum blended confidence required for
  a verdict of *vulnerable*. Lower it (e.g. `0.4`) for high-stakes templates where a
  partial signal is still actionable; raise it for noisy categories.
- `signals_blend` (default `0.5`): when a template ships its own matchers, the global
  signal bank is mixed in at this scaling factor — final confidence is
  `max(template_score, signals_blend × signal_score)`. Set to `0.0` to rely purely
  on template matchers; set to `1.0` for the strongest global-signal contribution.
- A template can override the threshold for itself via `info.threshold_override` and
  opt out of the global signal bank via `info.signals: false`.

### Attack selection

Pick the templates to run from the command line — the scan config no longer
enumerates them:

```bash
python run.py scan -t config/targets/openai_target.yaml --folder jailbreak
python run.py scan -t config/targets/openai_target.yaml --template system-prompt-leak-cot
python run.py scan -t config/targets/openai_target.yaml --tags safety-bypass,roleplay
```

Multiple selectors combine with **AND**. Drop them all to run the entire 236-template tree.

---

## Target Configuration Files

The `config/targets/` directory ships ready-to-use example YAMLs for ~40
LLM platforms — point YULA at any of them out of the box. See the
[supported platforms matrix](target_types.md) for the full list mapping
each platform to its target type and example file.

### OpenAI-compatible (`type: openai`)

Works with OpenAI, local llama.cpp, LM Studio, Ollama, vLLM, xAI Grok,
DeepSeek, Fireworks, Cerebras, SambaNova, NVIDIA NIM, Databricks,
Moonshot, Zhipu, DashScope, Hyperbolic, and any other server speaking
the `/v1/chat/completions` schema.

```yaml
type: openai

endpoint:
  url: "http://localhost:8080/v1/chat/completions"
  model: "gpt-4o"
  system_prompt: "You are a helpful assistant."   # optional system prompt injection
  max_tokens: 1024
  temperature: 0.7
  extra_headers: {}

auth:
  type: api_key
  api_key: "${OPENAI_API_KEY}"      # from environment variable

options: {}
```

### Anthropic (`type: anthropic`)

```yaml
type: anthropic

endpoint:
  url: "https://api.anthropic.com/v1/messages"
  model: "claude-3-5-sonnet-20241022"
  system_prompt: "You are a helpful assistant."
  max_tokens: 1024
  anthropic_version: "2023-06-01"

auth:
  type: api_key
  api_key: "${ANTHROPIC_API_KEY}"
```

### Custom REST API (`type: custom_api`)

For any AI that accepts HTTP requests with a configurable body:

```yaml
type: custom_api

endpoint:
  url: "http://localhost:9000/api/chat"
  method: POST
  body_template: |
    {
      "message": "{prompt}",
      "session_id": "yula-ai-scanner-test",
      "stream": false
    }
  response_path: "response.text"     # dot-notation path into the JSON response
  content_type: "application/json"
  extra_headers:
    X-App-Version: "1.0"

auth:
  type: bearer
  token: "${MY_API_TOKEN}"
```

The `{prompt}` placeholder in `body_template` is replaced with each attack payload.
`response_path` uses dot notation (e.g. `choices.0.message.content`) to extract the
response text from nested JSON.

### Web Page with Input Field (`type: webpage`)

Uses Playwright to interact with a real browser. Two equivalent styles are
supported — see [docs/target_types.md](target_types.md#web-page-type-webpage)
for the full reference. **Shorthand** for simple chat UIs:

```yaml
type: webpage

endpoint:
  url: "http://localhost:3000/chat"
  browser: chromium               # chromium | firefox | webkit
  headless: true                  # false to watch the browser (debugging)
  input_field: "#chat-input"
  submit_button: "#send-btn"      # null → press Enter instead
  response_container: ".message.assistant:last-child"
  clear_button: null              # optional: CSS selector to clear chat
  response_wait_ms: 8000          # max ms to wait for response

auth:
  type: cookie
  cookies:
    - name: "session_token"
      value: "${SESSION_TOKEN}"
      domain: "localhost"
      path: "/"
      secure: false
```

**Flow style** for multi-step setup, hidden / CSRF fields, multiple inputs,
custom waits, or custom extraction (HTML / attribute / regex / JS):

```yaml
type: webpage

endpoint:
  url: "http://localhost:3000/chat"
  browser:
    engine: chromium
    headless: true
    navigation_wait: networkidle
  setup:
    - { action: wait, selector: "#chat-input", state: visible }
    - { action: extract, selector: "input[name=csrf]",
        extract_method: attribute, attribute: value, store_as: csrf }
  prompt:
    inputs:
      - { selector: "input[name=csrf]", value: "{csrf}" }
      - { selector: "#chat-input",      value: "{prompt}" }
    submit: { method: click, selector: "#send-btn" }
    wait_for: { selector: ".message.assistant", state: visible, timeout_ms: 8000 }
    extract: { method: inner_text, pick: last }
    reset:   { action: none }

auth:
  type: none
```

Mixing the two styles in one file (e.g. `prompt:` plus `input_field:`) is
rejected with a clear error.

---

## Environment Variable Interpolation

Any value in either YAML file can reference environment variables using
`${VAR_NAME}` syntax. The variable is resolved at startup — if the variable
is missing, YULA AI Scanner exits immediately with an error message rather than
failing silently mid-scan.

```bash
export OPENAI_API_KEY=sk-...
export SESSION_TOKEN=abc123
python run.py scan --target config/targets/my_target.yaml
```

You can also use a `.env` file (requires `python-dotenv`):

```
# .env
OPENAI_API_KEY=sk-...
SESSION_TOKEN=abc123
```

---

## CLI Flag Overrides

Most `scan.yaml` values can be overridden from the command line:

```bash
python run.py scan \
  --target config/targets/openai_target.yaml \
  --folder jailbreak \
  --tags safety-bypass \
  --threshold 0.6 \
  --max-payloads 50 \
  --output output/custom_report.md \
  -vv
```

| Flag | Overrides | Notes |
|------|-----------|-------|
| `--config`, `-c` | — | Path to `scan.yaml` (default `config/scan.yaml`) |
| `--template`, `-T <id>` | template selection | Run only the template with this exact `id` |
| `--folder`, `-F <name>` | template selection | Run only templates under `templates/<name>/` |
| `--tags <a,b>` | template selection | Templates must have **all** listed tags |
| `--threshold <0.1..0.95>` | `scan.vulnerability_threshold` | Confidence cutoff for vulnerable verdict |
| `--max-payloads <N>` | `scan.max_payloads` | Cap total payload count |
| `--output`, `-o <path>` | `output.report_path` | Markdown path; JSON sibling auto-generated |
| `--visibility <level>` | `scan.visibility` | `public` \| `internal` \| `confidential` \| `debug` |
| `-v` / `-vv` / `-vvv` / `-vvvv` | `scan.visibility` | Repeatable shortcut (see below) |
| `--continue` | — | Resume; skip templates already tested cleanly against this target |

`--template`, `--folder`, and `--tags` combine with **AND** semantics.

### Verbosity (`-v` / `-vv` / `-vvv` / `-vvvv`)

The `-v` flag is repeatable and controls per-test streaming output. It overrides
`scan.visibility` from `scan.yaml` for the duration of the run:

```bash
python run.py scan -t config/targets/openai_target.yaml -v      # vulnerable findings only + HTTP exchange
python run.py scan -t config/targets/openai_target.yaml -vv     # every tested template
python run.py scan -t config/targets/openai_target.yaml -vvv    # full prompt, response, evaluation
python run.py scan -t config/targets/openai_target.yaml -vvvv   # also print every HTTP request/response, including failures
```

The explicit `--visibility <level>` flag (no short form) still works and takes
precedence over `-v` if both are supplied. The log file always captures every
exchange regardless of verbosity — verbosity only affects what is mirrored to
the console.

### Resumable scans (`--continue`)

YULA persists per-target scan state under `output/state/<target_key>.json`. When
you re-run with `--continue`, templates that already produced a clean verdict
against the same target URL are skipped, and only new or previously-errored
templates run. Drop the flag to force a full re-run.
