#!/usr/bin/env bash
# Refreshes the committed contract fixtures (demo/transcripts/) from the transcripts the last
# `mvn verify` recorded under demo/target/transcripts/ (see TranscriptRecorder.java).
# Every test's transcript is kept; curate by editing the EXCLUDE list below.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=target/transcripts
DST=transcripts
EXCLUDE=()   # e.g. ("NativeAuthIT.someNoisyTest.json")

[[ -d "$SRC" ]] || { echo "no $SRC: run 'mvn verify' (needs Docker) first" >&2; exit 1; }
mkdir -p "$DST"
find "$DST" -maxdepth 1 -name '*.json' -delete
for f in "$SRC"/*.json; do
  name=$(basename "$f")
  skip=false
  for e in "${EXCLUDE[@]:-}"; do [[ "$name" == "$e" ]] && skip=true; done
  $skip || cp "$f" "$DST/$name"
done
echo "$(ls "$DST"/*.json | wc -l | tr -d ' ') transcripts in $DST"
