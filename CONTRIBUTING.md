# Contributing to YULA AI Scanner

Thanks for considering a contribution. YULA's value scales with its template
library and platform coverage — bug reports, new attack templates, new target
adapters, and documentation improvements are all welcome.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
By participating you agree to its terms.

## Reporting bugs

For functional bugs (broken scan, parsing error, false positive, etc.):
open a GitHub issue using the **Bug report** template.

For security vulnerabilities **in YULA itself** (RCE in the scanner,
credential leak from a target YAML, etc.): **do not open a public issue.**
Use the private disclosure process documented in [SECURITY.md](SECURITY.md).

## Development setup

YULA targets Python 3.11+ but is developed primarily on 3.13.

```bash
git clone https://github.com/0xihsn/yulaai.git
cd yulaai
python3.13 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Optional — needed only if you touch the webpage adapter or write
# webpage-target tests:
playwright install chromium
```

Run the test suite:

```bash
python3.13 -m pytest tests/ -v
```

## Pull request flow

1. **Fork** the repository on GitHub.
2. **Branch** from `main`: `git checkout -b feat/short-description`.
3. **Code & test** — keep changes focused; one PR = one logical change.
4. **Run the suite** (`pytest tests/ -v`) — every change must keep the
   suite green. Add tests for any new behaviour.
5. **Commit** with a Conventional-Commits-style message
   (`feat: …`, `fix: …`, `docs: …`, `test: …`, `refactor: …`).
6. **Push** and open a PR using the template. Link any related issues.
7. **CI** must pass before merge. Maintainer reviews follow.

## Adding a new attack template

1. Pick the right category directory under [`templates/`](templates/) — or
   add a new one if no existing intent fits. Use the parent-directory name
   as the `attack.intent` value.
2. Read [docs/template_authoring.md](docs/template_authoring.md) — it
   covers the schema, FP/FN heuristics, and matcher pitfalls.
3. Make sure `info.source` / `info.source_url` / `info.source_license`
   are filled (the existing 226 templates derive from the
   [Arc PI Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy),
   CC-BY-4.0). For wholly original templates, fill these with your own
   provenance instead of removing them.
4. The `tests/test_template_quality.py` regression suite enforces
   structural rules (≥3 payloads, ≥1 refusal matcher, no naked
   placeholders, attribution present, etc.). Run it locally before
   pushing.

## Adding a new target / LLM platform

1. Most commercial LLM APIs are OpenAI-compatible — start by copying an
   existing example like
   [`config/targets/groq_target.yaml`](config/targets/groq_target.yaml)
   and changing the URL, model, and env-var name. No code changes are
   needed.
2. For non-OpenAI request shapes, copy
   [`config/targets/custom_api_target.yaml`](config/targets/custom_api_target.yaml)
   and write the body template + response-path JSON pointer.
3. For browser-driven targets, copy
   [`config/targets/webpage_target.yaml`](config/targets/webpage_target.yaml)
   and update the selectors. Selectors *will* break on UI redesigns —
   include `fallback_selectors` and a comment pointing to where you
   captured them.
4. Add a row to the supported-platforms matrix in
   [docs/target_types.md](docs/target_types.md).

## Style

- Python: pre-existing style (no formatter enforced; match surrounding
  code). Type hints on public APIs. No new comments unless they explain
  *why*, not *what*.
- YAML templates: 2-space indent. Quoted strings only when needed
  (special characters, leading sigils).
- Don't introduce new dependencies without discussion.

## License

By contributing you agree that your contributions are licensed under the
project's GPL-3.0-or-later license (see [LICENSE](LICENSE)).
