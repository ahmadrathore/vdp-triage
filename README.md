# VDP Triage
Standalone reviewer edition for Python 3.10+. No Python packages required.

Run the synthetic exercise with a local Ollama installation and an installed model:
    python triage.py --report example.txt --model llama3.2

The report goes to Ollama on loopback. Review the proposed metrics against the report before accepting them. The rationale is model-generated. Scoring is deterministic and does not establish whether a finding is genuine.

To reproduce the expected synthetic assessment without a model:
    python triage.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Expected: 7.5 High. Change PR:N to PR:L to see how requiring a low-privilege account changes the score to 6.5. This edition includes the original scoring core and a standalone model adapter. Private review build. Public release and licensing pending.

Documentation: [Tool and limitations](docs/overview.md) | [Installation](docs/install.md) | [Reviewer demo](docs/demo.md)
