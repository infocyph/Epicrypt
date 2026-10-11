#!/usr/bin/env bash
# Compare two deployed, semantically identical HTTP workloads on matched host infrastructure.
set -euo pipefail
export LC_ALL=C
if (( $# != 2 )); then
  echo "Usage: HOST_BASE_PID=N HOST_CANDIDATE_PID=N $0 BASE_URL CANDIDATE_URL" >&2
  exit 2
fi
for exe in wrk curl awk ps sort grep; do
  command -v "$exe" >/dev/null || { echo "Missing executable: $exe" >&2; exit 2; }
done
: "${HOST_BASE_PID:?Set baseline FPM/server parent PID}"
: "${HOST_CANDIDATE_PID:?Set candidate FPM/server parent PID}"
rounds=${HOST_ROUNDS:-5}
threads=${HOST_THREADS:-2}
connections=${HOST_CONNECTIONS:-16}
duration=${HOST_DURATION:-20s}
report=${HOST_REPORT:-host-performance.tsv}
: "${HOST_EXPECTED_BODY:?Set the independently verified static response body expected from every HTTP request}"
export HOST_EXPECTED_BODY
validation_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/host-rpm-validate.lua"
[[ -f "$validation_script" ]] || { echo "Missing wrk validation script: $validation_script" >&2; exit 2; }
[[ $rounds =~ ^[0-9]+$ ]] && (( rounds >= 3 && rounds % 2 == 1 )) || { echo "Choose at least 3 odd rounds" >&2; exit 2; }
[[ $threads =~ ^[0-9]+$ ]] && (( threads >= 1 )) || exit 2
[[ $connections =~ ^[0-9]+$ ]] && (( connections >= threads )) || exit 2
for pid in "$HOST_BASE_PID" "$HOST_CANDIDATE_PID"; do
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null || { echo "Inactive server PID: $pid" >&2; exit 2; }
done
for url in "$1" "$2"; do
  body=$(curl -fsS --max-time 10 "$url") || exit 1
  if [[ "$body" != "$HOST_EXPECTED_BODY" ]]; then
    echo "Incorrect preflight response from $url" >&2
    exit 1
  fi
done
rss_kib() {
  ps -eo pid=,ppid=,rss= | awk -v master="$1" '
    {if ($3 !~ /^[0-9]+$/) bad=1; parent[$1]=$2; resident[$1]=$3; all[$1]=1}
    END {for(id in all) {p=id; for(n=0;n<256 && p in parent;n++) {
      if (p==master) {total+=resident[id]; break}
      p=parent[p]
    }} if(bad || total<=0) {print "Invalid or missing process-tree RSS in KiB" > "/dev/stderr"; exit 1} print total+0}'
}
sample() {
  local variant=$1 url=$2 master=$3 round=$4 log proc peak=0 current metrics
  local marker valid invalid completed connect read_errors write_errors timeout elapsed_us p50 p95 p99
  log=$(mktemp)
  wrk -t"$threads" -c"$connections" -d"$duration" --latency \
    -s "$validation_script" "$url" > "$log" 2>&1 &
  proc=$!
  while kill -0 "$proc" 2>/dev/null; do
    current=$(rss_kib "$master")
    (( current > peak )) && peak=$current
    sleep 0.25
  done
  if ! wait "$proc"; then cat "$log" >&2; rm -f "$log"; return 1; fi
  current=$(rss_kib "$master")
  (( current > peak )) && peak=$current
  metrics=$(grep '^EPICRYPT_WRK ' "$log") || {
    cat "$log" >&2
    echo "Missing per-response validation results" >&2
    rm -f "$log"
    return 1
  }
  if [[ $(printf '%s\n' "$metrics" | wc -l) -ne 1 ]]; then
    echo "Ambiguous wrk response-validation results" >&2
    rm -f "$log"
    return 1
  fi
  read -r marker valid invalid completed connect read_errors write_errors timeout elapsed_us p50 p95 p99 <<< "$metrics"
  for value in "$valid" "$invalid" "$completed" "$connect" "$read_errors" "$write_errors" "$timeout" "$elapsed_us" "$p50" "$p95" "$p99"; do
    if ! [[ $value =~ ^[0-9]+$ ]]; then
      cat "$log" >&2
      echo "Invalid wrk evidence: $value" >&2
      rm -f "$log"
      return 1
    fi
  done
  if (( valid == 0 || valid != completed || invalid != 0 || connect != 0 || read_errors != 0 || write_errors != 0 || timeout != 0 || elapsed_us == 0 )); then
    cat "$log" >&2
    echo "Incomplete/incorrect responses or transport errors: $metrics" >&2
    rm -f "$log"
    return 1
  fi
  if [[ -n ${HOST_MAX_RSS_KIB:-} ]]; then
    [[ $HOST_MAX_RSS_KIB =~ ^[0-9]+$ ]] || { echo "Invalid HOST_MAX_RSS_KIB" >&2; return 2; }
    if (( peak > HOST_MAX_RSS_KIB )); then
      echo "Host process-tree memory exceeds HOST_MAX_RSS_KIB: $peak" >&2
      rm -f "$log"
      return 1
    fi
  fi
  awk -v name="$variant" -v round="$round" -v valid="$valid" -v elapsed="$elapsed_us" \
    -v rss="$peak" -v p50="$p50" -v p95="$p95" -v p99="$p99" 'BEGIN {
    printf "%s\t%d\t%.3f\t%d\t%.3f\t%.3f\t%.3f\t%d\t%.3f\n",
      name, round, valid*60000000/elapsed, rss, p50/1000, p95/1000, p99/1000,
      valid, elapsed/1000000
  }' >> "$report"
  rm -f "$log"
}
printf 'variant\tround\tsuccessful_rpm\tpeak_tree_rss_kib\tp50_ms\tp95_ms\tp99_ms\tvalidated_requests\tduration_s\n' > "$report"
for ((i=1;i<=rounds;i++)); do
  if (( i % 2 )); then
    sample baseline "$1" "$HOST_BASE_PID" "$i"
    sample candidate "$2" "$HOST_CANDIDATE_PID" "$i"
  else
    sample candidate "$2" "$HOST_CANDIDATE_PID" "$i"
    sample baseline "$1" "$HOST_BASE_PID" "$i"
  fi
done
awk -F '\t' 'NR>1 { if (!($1 in low) || $3<low[$1]) low[$1]=$3; if ($3>high[$1]) high[$1]=$3 }
  END { for (v in low) { if (low[v]<=0 || high[v]/low[v]>1.05) { print "FAIL: unstable trial spread (>5%):",v; exit 1 } } }' "$report"
median() {
  awk -F '\t' -v kind="$1" 'NR>1 && $1==kind {print $3}' "$report" |
    sort -n | awk '{a[NR]=$1} END {if(NR%2) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2}'
}
base=$(median baseline)
candidate=$(median candidate)
awk -v a="$base" -v b="$candidate" 'BEGIN {
  if(a<=0 || b<=0) exit 2
  printf "Baseline median successful RPM: %.2f\nCandidate median successful RPM: %.2f\nRegression: %+.3f%%\n",a,b,(b/a-1)*100
  if(b<a*0.98) {print "FAIL: >2% median successful-RPM regression"; exit 1}
  print "PASS: <=2% median successful-RPM regression (check measured variance and host equivalence)"
}'
