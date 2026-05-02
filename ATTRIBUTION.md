# Attribution

YULA AI Scanner is licensed under the **GNU General Public License v3.0 or
later** (see [LICENSE](LICENSE)).

The scanner ships with adversarial-prompt templates and a taxonomy of attack
intents/techniques/evasions that derive from third-party work credited below.
This file is the canonical place to look for license-required attribution.

---

## Arc PI Taxonomy — Jason Haddix / Arcanum Information Security

A large fraction of the YAML templates under [`templates/`](templates/) — and
the broader intent / technique / evasion taxonomy YULA uses to organise them —
were generated using or derived from the **Arc PI Taxonomy** created by
**Jason Haddix** of **Arcanum Information Security**.

The Arc PI Taxonomy is licensed under a
[Creative Commons Attribution 4.0 International License (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/).

> This content/methodology is based on the Arc PI Taxonomy created by
> Jason Haddix of Arcanum Information Security.

- **Original work:** Arc PI Taxonomy
- **Author:** Jason Haddix — Arcanum Information Security
- **Source:** <https://github.com/Arcanum-Sec/arc_pi_taxonomy>
- **License:** [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)
- **Changes made:** Templates were re-encoded as YULA-compatible YAML
  Matchers were authored from scratch by the YULA project.
  Some payloads were paraphrased, translated, or expanded for additional
  language / encoding coverage. Additional categories not present in the
  original taxonomy (e.g. truncation-aware DoS) were added.

### Template categories derived from Arc PI

The following directories under [`templates/`](templates/) contain templates
that are direct derivatives of Arc PI Taxonomy entries — i.e. their
category name appears in the Arc PI taxonomy itself — and are therefore
subject to the CC-BY-4.0 attribution requirement:

| Directory | Arc PI Category |
|---|---|
| [`templates/jailbreak/`](templates/jailbreak/) | Jailbreak (intent) |
| [`templates/system_prompt_leak/`](templates/system_prompt_leak/) | System Prompt Leak (intent) |
| [`templates/get_prompt_secret/`](templates/get_prompt_secret/) | Get Prompt Secret (intent) |
| [`templates/discuss_harm/`](templates/discuss_harm/) | Discuss Harm (intent) |
| [`templates/denial_of_service/`](templates/denial_of_service/) | Denial of Service (intent) |
| [`templates/data_poisoning/`](templates/data_poisoning/) | Data Poisoning (intent) |
| [`templates/business_integrity/`](templates/business_integrity/) | Business Integrity (intent) |
| [`templates/test_bias/`](templates/test_bias/) | Bias (intent) |
| [`templates/multi_chain_attacks/`](templates/multi_chain_attacks/) | Multi-Chain Attacks (intent) |
| [`templates/api_enumeration/`](templates/api_enumeration/) | API Enumeration (intent) |
| [`templates/tool_enumeration/`](templates/tool_enumeration/) | Tool Enumeration (intent) |
| [`templates/generate_image/`](templates/generate_image/) | Generate Harmful Image (intent) |
| [`templates/evasions/`](templates/evasions/) | Attack Evasions (top-level) |
| [`templates/techniques/`](templates/techniques/) | Attack Techniques (top-level) |

Each individual YAML in those directories carries an `info.source`,
`info.source_url`, and `info.source_license` field with the same attribution.

### YULA-original categories (inspired by Arc PI, not direct derivatives)

Most of YULA's other attack categories were **inspired by** Arc PI
Taxonomy's overall framing and methodology, but their category names do not
appear in the Arc PI taxonomy and the templates were authored from scratch
for YULA. They are not direct derivatives of any specific Arc PI entry, so
the per-template `source` / `source_url` / `source_license` fields are
intentionally omitted. The taxonomy-level inspiration is credited here at
the project level rather than per file:

- [`templates/attack_external_systems/`](templates/attack_external_systems/)
- [`templates/attack_external_users/`](templates/attack_external_users/)
- [`templates/attack_internal_systems/`](templates/attack_internal_systems/)
- [`templates/attack_internal_users/`](templates/attack_internal_users/)
- [`templates/authorized_advice_exploitation/`](templates/authorized_advice_exploitation/)
- [`templates/cbrne_information/`](templates/cbrne_information/)
- [`templates/child_safety/`](templates/child_safety/)
- [`templates/election_political/`](templates/election_political/)
- [`templates/excessive_agency/`](templates/excessive_agency/)
- [`templates/hallucination/`](templates/hallucination/)
- [`templates/hate_speech/`](templates/hate_speech/)
- [`templates/insecure_code/`](templates/insecure_code/)
- [`templates/supply_chain/`](templates/supply_chain/)
- [`templates/vector_embedding/`](templates/vector_embedding/)

---

## Other Sources

- **GNU GPLv3 license text** — Free Software Foundation,
  <https://www.gnu.org/licenses/gpl-3.0.txt>, distributed verbatim per the
  FSF's terms.
- **GPLv3 license badge / SPDX identifiers** — public-domain identifiers
  from the SPDX project.

---

## How to attribute YULA AI Scanner downstream

If you redistribute YULA, modify it, or build derivative tooling, you must
comply with both:

1. **GPLv3** — keep source open, ship the [LICENSE](LICENSE) file, mark
   modifications.
2. **CC-BY-4.0** — keep the Arc PI Taxonomy attribution intact (this file
   plus the per-template `source` fields).

A suggested credit line for derivative work:

> Built on YULA AI Scanner (GPL-3.0-or-later) by Ihsan Bilkay, which
> incorporates templates derived from the Arc PI Taxonomy (CC-BY-4.0) by
> Jason Haddix / Arcanum Information Security.
