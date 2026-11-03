#!/usr/bin/env bash
# Deterministic parser and rejection regressions; not performance measurements.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cat > "$scratch/curl" <<'STUB'
#!/usr/bin/env bash
printf 'release-health-ok'
STUB
cat > "$scratch/wrk" <<'STUB'
#!/usr/bin/env bash
if [[ ${HOST_MOCK_SCENARIO:-pass} == drift || ${HOST_MOCK_SCENARIO:-pass} == paired_regression || ${HOST_MOCK_SCENARIO:-pass} == masked_regression ]]; then
  kind=baseline
  if [[ " $* " == *" http://candidate.test/ "* ]]; then kind=candidate; fi
  counter="$HOST_MOCK_COUNTER-$kind"
  count=$(cat "$counter" 2>/dev/null || printf 0)
  ((count+=1))
  printf '%d' "$count" > "$counter"
  # Reproduce the 2cf0d90 A/A measurements, rounded to whole RPM.
  case "$count" in
    1) valid=21081; candidate=21160 ;;
    2) valid=20439; candidate=20369 ;;
    3) valid=20925; candidate=20233 ;;
  esac
  if [[ $HOST_MOCK_SCENARIO == masked_regression ]]; then
    # Independent medians hide two losing pairs as a +1.5% improvement.
    case "$count" in
      1) valid=10000; candidate=9750 ;;
      2) valid=10000; candidate=10150 ;;
      3) valid=10400; candidate=10150 ;;
    esac
  fi
  if [[ $kind == candidate ]]; then
    if [[ $HOST_MOCK_SCENARIO == paired_regression ]]; then valid=$((valid * 975 / 1000)); else valid=$candidate; fi
  fi
  echo "EPICRYPT_WRK $valid 0 $valid 0 0 0 0 60000000 1000 1500 2000"
  exit
fi
case " $* " in
  *" http://candidate.test/ "*)
    case "${HOST_MOCK_SCENARIO:-pass}" in
      regression) echo 'EPICRYPT_WRK 100 0 100 0 0 0 0 1040000 1000 1500 2000' ;;
      boundary) echo 'EPICRYPT_WRK 98 0 98 0 0 0 0 1000000 1000 1500 2000' ;;
      over_budget) echo 'EPICRYPT_WRK 97999 0 97999 0 0 0 0 1000000000 1000 1500 2000' ;;
      wrong_body) echo 'EPICRYPT_WRK 99 1 100 0 0 0 0 1000000 1000 1500 2000' ;;
      socket_error) echo 'EPICRYPT_WRK 100 0 100 0 1 0 0 1000000 1000 1500 2000' ;;
      missing_validation) echo 'Requests/sec: 1000.00' ;;
      unstable)
        count=$(cat "$HOST_MOCK_COUNTER" 2>/dev/null || printf 0)
        ((count+=1))
        printf '%d' "$count" > "$HOST_MOCK_COUNTER"
        elapsed=1000000
        if ((count==3)); then elapsed=1100000; fi
        echo "EPICRYPT_WRK 100 0 100 0 0 0 0 $elapsed 1000 1500 2000" ;;
      *) echo 'EPICRYPT_WRK 100 0 100 0 0 0 0 1000000 1000 1500 2000' ;;
    esac ;;
  *) echo 'EPICRYPT_WRK 100 0 100 0 0 0 0 1000000 1000 1500 2000' ;;
esac
STUB
cat > "$scratch/ps" <<'STUB'
#!/usr/bin/env bash
if [[ ${HOST_MOCK_SCENARIO:-pass} == memory_units ]]; then
  printf '%s 0 10m\n' "$HOST_BASE_PID"
else
  exec /bin/ps "$@"
fi
STUB
chmod +x "$scratch/curl" "$scratch/wrk" "$scratch/ps"
execute() {
  rm -f "$scratch/counter" "$scratch/counter-baseline" "$scratch/counter-candidate"
  HOST_MOCK_SCENARIO="$1" HOST_EXPECTED_BODY=release-health-ok \
  HOST_MOCK_COUNTER="$scratch/counter" \
  HOST_BASE_PID=$$ HOST_CANDIDATE_PID=$$ \
  HOST_ROUNDS=3 HOST_DURATION=1s HOST_REPORT="$scratch/compare.tsv" \
  PATH="$scratch:$PATH" bash "$root/benchmarks/host-rpm-compare.sh" \
    http://baseline.test/ http://candidate.test/ > "$scratch/output" 2>&1
}
execute pass || { cat "$scratch/output" >&2; exit 1; }
grep -Fq 'PASS: <=2% median successful-RPM regression' "$scratch/output"
execute drift || { cat "$scratch/output" >&2; exit 1; }
execute boundary || { cat "$scratch/output" >&2; exit 1; }
for scenario in regression paired_regression masked_regression over_budget wrong_body socket_error missing_validation memory_units unstable; do
  if execute "$scenario"; then
    echo "Comparator incorrectly accepted failure: $scenario" >&2
    exit 1
  fi
done
echo 'Matched-host comparator pass/drift/boundary and nine negative cases passed.'
