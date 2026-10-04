#!/bin/sh
# GAOP v0.7.0 entrypoint. Safe idle/default: serves the owner Ingress panel and processes bounded
# control envelopes only. It NEVER replays the Gate A/B/C/H or Phase 0.5C harnesses.
set -eu
exec python3 /gaop_core.py serve
