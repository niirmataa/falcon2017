#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run reproducible libFuzzer campaigns on the GNU/Linux research host.

Usage:
  scripts/run_gnu_fuzz_campaign.sh [options]

Options:
  --target <name>       Run only the named target. Repeat to select multiple.
  --time <seconds>      Per-target fuzzing time budget. Default: 1800.
  --jobs <count>        libFuzzer job count. Default: 1.
  --run-dir <path>      Output directory. Default: artifacts/fuzz/runs/<timestamp>.
  --sanitizer <name>    cargo-fuzz sanitizer. Default: address.
  --target-triple <t>   Build target triple. Default: x86_64-unknown-linux-gnu.
  --help                Show this message.
EOF
}

json_array() {
  local first=1
  local item
  printf '['
  for item in "$@"; do
    if [[ $first -eq 0 ]]; then
      printf ', '
    fi
    printf '"%s"' "$item"
    first=0
  done
  printf ']'
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_TOTAL_TIME=1800
JOBS=1
SANITIZER=address
TARGET_TRIPLE=x86_64-unknown-linux-gnu
RUN_DIR=""
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGETS+=("$2")
      shift 2
      ;;
    --time)
      MAX_TOTAL_TIME="$2"
      shift 2
      ;;
    --jobs)
      JOBS="$2"
      shift 2
      ;;
    --run-dir)
      RUN_DIR="$2"
      shift 2
      ;;
    --sanitizer)
      SANITIZER="$2"
      shift 2
      ;;
    --target-triple)
      TARGET_TRIPLE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=(decode_signature decode_public_key decode_secret_key verify)
fi

if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$ROOT/artifacts/fuzz/runs/$(date -u +%Y%m%dT%H%M%SZ)"
fi

mkdir -p "$RUN_DIR"/{logs,artifacts,corpus,minimized-crashes}

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required" >&2
  exit 2
fi

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required" >&2
  exit 2
fi

if ! rustup toolchain list | grep -q '^nightly'; then
  echo "nightly toolchain is required" >&2
  exit 2
fi

cargo +nightly fuzz list --fuzz-dir fuzz >/dev/null

cat >"$RUN_DIR/metadata.json" <<EOF
{
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(uname -srvmo)",
  "sanitizer": "$SANITIZER",
  "target_triple": "$TARGET_TRIPLE",
  "jobs": $JOBS,
  "max_total_time": $MAX_TOTAL_TIME,
  "targets": $(json_array "${TARGETS[@]}")
}
EOF

overall_status=0

for target in "${TARGETS[@]}"; do
  seed_corpus="$ROOT/fuzz/corpus/$target"
  run_corpus="$RUN_DIR/corpus/$target"
  artifact_dir="$RUN_DIR/artifacts/$target"
  minimized_dir="$RUN_DIR/minimized-crashes/$target"
  log_file="$RUN_DIR/logs/$target.log"
  status_file="$RUN_DIR/logs/$target.status"

  mkdir -p "$run_corpus" "$artifact_dir" "$minimized_dir"
  if [[ -d "$seed_corpus" ]]; then
    cp -a "$seed_corpus"/. "$run_corpus"/
  fi

  {
    echo "target=$target"
    echo "started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "seed_corpus=$seed_corpus"
    echo "run_corpus=$run_corpus"
    echo "artifact_dir=$artifact_dir"
    echo "minimized_dir=$minimized_dir"
    echo "max_total_time=$MAX_TOTAL_TIME"
    echo "sanitizer=$SANITIZER"
    echo "target_triple=$TARGET_TRIPLE"
    echo "jobs=$JOBS"
    echo
  } >"$log_file"

  set +e
  cargo +nightly fuzz run \
    --fuzz-dir fuzz \
    --sanitizer "$SANITIZER" \
    --target "$TARGET_TRIPLE" \
    --jobs "$JOBS" \
    "$target" \
    "$run_corpus" \
    -- \
    -max_total_time="$MAX_TOTAL_TIME" \
    -artifact_prefix="$artifact_dir/" \
    -print_final_stats=1 \
    >>"$log_file" 2>&1
  target_status=$?
  set -e

  printf '%s\n' "$target_status" >"$status_file"
  if [[ $target_status -ne 0 ]]; then
    overall_status=1
  fi

  while IFS= read -r -d '' crash; do
    crash_name="$(basename "$crash")"
    minimized_path="$minimized_dir/$crash_name"
    cp "$crash" "$minimized_path"
    set +e
    cargo +nightly fuzz tmin \
      --fuzz-dir fuzz \
      --sanitizer "$SANITIZER" \
      --target "$TARGET_TRIPLE" \
      "$target" \
      "$minimized_path" \
      -- \
      -runs=255 \
      >>"$log_file" 2>&1
    tmin_status=$?
    set -e
    printf '%s %s\n' "$crash_name" "$tmin_status" >>"$RUN_DIR/logs/$target.tmin"
  done < <(find "$artifact_dir" -maxdepth 1 -type f -print0 | sort -z)
done

exit "$overall_status"
