# Tool and limitations
VDP Triage helps a disclosure analyst inspect the assumptions behind a CVSS v3.1 Base score. It accepts a proposed vector or asks a local model to read a plain-text report. The original scoring core validates all eight metrics and computes severity. An analyst can supply an alternative vector to see each changed metric and both scores.

The local Ollama process receives the report. This edition has no database, attachment parser, authentication or decision history. Treat model rationale as unverified. The operator decides whether each metric follows from the evidence. Use synthetic inputs for the conference.

## Changes
This reviewer edition adds a command-line analyst comparison to the standalone scoring and model adapter. No open-source license has been recorded in this edition.
