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
case " $* " in
  *" http://candidate.test/ "*)
    case "${HOST_MOCK_SCENARIO:-pass}" in
      regression) echo 'EPICRYPT_WRK 100 0 100 0 0 0 0 1040000 1000 1500 2000' ;;
      wrong_body) echo 'EPICRYPT_WRK 99 1 100 0 0 0 0 1000000 1000 1500 2000' ;;
      socket_error) echo 'EPICRYPT_WRK 100 0 100 0 1 0 0 1000000 1000 1500 2000' ;;
      missing_validation) echo 'Requests/sec: 1000.00' ;;
      *) echo 'EPICRYPT_WRK 100 0 100 0 0 0 0 1000000 1000 1500 2000' ;;
    esac ;;
  *) echo 'EPICRYPT_WRK 100 0 100 0 0 0 0 1000000 1000 1500 2000' ;;
esac
STUB
chmod +x "$scratch/curl" "$scratch/wrk"
execute() {
  HOST_MOCK_SCENARIO="$1" HOST_EXPECTED_BODY=release-health-ok \
  HOST_BASE_PID=$$ HOST_CANDIDATE_PID=$$ \
  HOST_ROUNDS=3 HOST_DURATION=1s HOST_REPORT="$scratch/compare.tsv" \
  PATH="$scratch:$PATH" bash "$root/benchmarks/host-rpm-compare.sh" \
    http://baseline.test/ http://candidate.test/ > "$scratch/output" 2>&1
}
execute pass || { cat "$scratch/output" >&2; exit 1; }
grep -Fq 'PASS: <=2% median successful-RPM regression' "$scratch/output"
for scenario in regression wrong_body socket_error missing_validation; do
  if execute "$scenario"; then
    echo "Comparator incorrectly accepted failure: $scenario" >&2
    exit 1
  fi
done
echo 'Matched-host comparator positive and four negative cases passed.'
