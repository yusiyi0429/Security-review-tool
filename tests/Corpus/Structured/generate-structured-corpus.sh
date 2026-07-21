#!/usr/bin/env bash
# Generate structured format corpus fixtures for parser testing.
# Equivalent to: pwsh tests/Corpus/Structured/generate-structured-corpus.ps1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR"

echo "Generating structured corpus fixtures in: $OUTPUT_DIR"

python3 "$SCRIPT_DIR/generate_structured_corpus.py" "$OUTPUT_DIR"

echo "Done."
