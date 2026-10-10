#!/usr/bin/env bash
# Compare two deployed, semantically identical HTTP workloads on matched host infrastructure.
set -euo pipefail
export LC_ALL=C
if (( $# != 2 )); then
  echo "Usage: HOST_BASE_PID=N HOST_CANDIDATE_PID=N $0 BASE_URL CANDIDATE_URL" >&2
  exit 2
fi
for exe in wrk curl awk ps sort; do
  command -v "$exe" >/dev/null || { echo "Missing executable: $exe" >&2; exit 2; }
done
: "${HOST_BASE_PID:?Set baseline FPM/server parent PID}"
: "${HOST_CANDIDATE_PID:?Set candidate FPM/server parent PID}"
rounds=${HOST_ROUNDS:-5}
threads=${HOST_THREADS:-2}
connections=${HOST_CONNECTIONS:-16}
duration=${HOST_DURATION:-20s}
report=${HOST_REPORT:-host-performance.tsv}
[[ $rounds =~ ^[0-9]+$ ]] && (( rounds >= 3 && rounds % 2 == 1 )) || { echo "Choose at least 3 odd rounds" >&2; exit 2; }
[[ $threads =~ ^[0-9]+$ ]] && (( threads >= 1 )) || exit 2
[[ $connections =~ ^[0-9]+$ ]] && (( connections >= threads )) || exit 2
for pid in "$HOST_BASE_PID" "$HOST_CANDIDATE_PID"; do
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null || { echo "Inactive server PID: $pid" >&2; exit 2; }
done
for url in "$1" "$2"; do
  body=$(curl -fsS --max-time 10 "$url") || exit 1
  if [[ -n ${HOST_EXPECTED_BODY:-} && "$body" != "$HOST_EXPECTED_BODY" ]]; then
    echo "Incorrect preflight response from $url" >&2
    exit 1
  fi
done
rss_kib() {
  ps -eo pid=,ppid=,rss= | awk -v master="$1" '
    {parent[$1]=$2; resident[$1]=$3; all[$1]=1}
    END {for(id in all) {p=id; for(n=0;n<256 && p in parent;n++) {
      if (p==master) {total+=resident[id]; break}
      p=parent[p]
    }} print total+0}'
}
sample() {
  local variant=$1 url=$2 master=$3 round=$4 log proc peak=0 current count rps errors=0 bad=0 p99
  log=$(mktemp)
  wrk -t"$threads" -c"$connections" -d"$duration" --latency "$url" > "$log" 2>&1 &
  proc=$!
  while kill -0 "$proc" 2>/dev/null; do
    current=$(rss_kib "$master")
    (( current > peak )) && peak=$current
    sleep 1
  done
  if ! wait "$proc"; then cat "$log" >&2; rm -f "$log"; return 1; fi
  current=$(rss_kib "$master")
  (( current > peak )) && peak=$current
  count=$(awk '/^[[:space:]]*[0-9]+ requests in / {print $1}' "$log")
  rps=$(awk '/Requests\/sec:/ {print $2}' "$log")
  bad=$(awk '/Non-2xx or 3xx responses:/ {print $5}' "$log")
  errors=$(awk '/Socket errors:/ {for(i=1;i<=NF;i++) if($i ~ /^[0-9]+,?$/) {gsub(/,/,"",$i); total+=$i}} END{print total+0}' "$log")
  bad=${bad:-0}
  if ! [[ "$count" =~ ^[0-9]+$ && "$rps" =~ ^[0-9]+([.][0-9]+)?$ && "$bad" =~ ^[0-9]+$ ]]; then
    cat "$log" >&2; rm -f "$log"; return 1
  fi
  if (( count == 0 || bad != 0 || errors != 0 )); then
    cat "$log" >&2; echo "Non-successful HTTP responses or socket errors" >&2
    rm -f "$log"; return 1
  fi
  p99=$(awk '/^[[:space:]]*99%/ {print $2}' "$log")
  awk -v name="$variant" -v round="$round" -v rps="$rps" -v rss="$peak" -v latency="${p99:-unknown}" 'BEGIN {
    printf "%s\t%d\t%.3f\t%d\t%s\n", name, round, rps*60, rss, latency
  }' >> "$report"
  rm -f "$log"
}
printf 'variant\tround\tsuccessful_rpm\tpeak_tree_rss_kib\tp99_latency\n' > "$report"
for ((i=1;i<=rounds;i++)); do
  if (( i % 2 )); then
    sample baseline "$1" "$HOST_BASE_PID" "$i"
    sample candidate "$2" "$HOST_CANDIDATE_PID" "$i"
  else
    sample candidate "$2" "$HOST_CANDIDATE_PID" "$i"
    sample baseline "$1" "$HOST_BASE_PID" "$i"
  fi
done
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
