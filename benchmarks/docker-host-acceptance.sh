#!/usr/bin/env bash
# Matched FPM acceptance against the preceding published release, with explicit historical overrides.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
report=${HOST_DOCKER_REPORT:-"$repo/var/docker-host-acceptance"}
mkdir -p "$report"
report="$(cd "$report" && pwd)"
scratch=$(mktemp -d)
prefix="epicrypt-release-$$"
php_image=${HOST_PHP_IMAGE:-php:8.4.26-fpm-alpine3.24}
tools_image=${HOST_TOOLS_IMAGE:-"$prefix-tools"}
baseline_ref=${HOST_BASELINE_REF:-3.2}
borrowed_ref=${HOST_BORROWED_BASELINE_REF:-$baseline_ref}
sampler=''
cleanup() {
  if [[ -n $sampler ]]; then kill "$sampler" 2>/dev/null || :; wait "$sampler" 2>/dev/null || :; fi
  docker logs "$prefix-fpm" > "$report/fpm.log" 2>&1 || :
  for role in soak client proxy fpm; do docker rm -f "$prefix-$role" >/dev/null 2>&1 || :; done
  docker network rm "$prefix" >/dev/null 2>&1 || :
  rm -rf "$scratch"
}
trap cleanup EXIT
git -C "$repo" rev-parse HEAD > "$report/candidate-parent-sha"
git -C "$repo" diff --binary > "$report/candidate.patch"
baseline_sha=$(git -C "$repo" rev-parse --verify --end-of-options "${baseline_ref}^{commit}")
borrowed_sha=$(git -C "$repo" rev-parse --verify --end-of-options "${borrowed_ref}^{commit}")
printf '%s\n' "$baseline_sha" > "$report/baseline-sha"
printf '%s\n' "$borrowed_sha" > "$report/borrowed-baseline-sha"
mkdir -p "$scratch/host"
cp "$repo/composer.json" "$repo/composer.lock" "$scratch/host/"
cp -a "$repo/src" "$scratch/host/"
(
  cd "$scratch/host"
  composer require 'infocyph/runwire:^3.0' 'nyholm/psr7:^1.8.2' --update-no-dev --no-interaction --no-progress --prefer-dist
) > "$report/install.log" 2>&1
cp "$scratch/host/composer.lock" "$report/host-composer.lock"
cp "$repo/benchmarks/host-workload.php" "$report/host-workload.fixture"
php -r 'require $argv[1]; $key=openssl_pkey_new(["private_key_type"=>OPENSSL_KEYTYPE_EC,"curve_name"=>"prime256v1"]); $public=openssl_pkey_get_details($key)["key"]; file_put_contents($argv[2],$public); echo json_encode(["keys"=>[(new Infocyph\Epicrypt\Token\Jwt\Jwks())->exportPublicKeyToJwk($public,"release",Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm::ES256)]],JSON_THROW_ON_ERROR);' "$repo/vendor/autoload.php" "$scratch/host-public.pem" > "$scratch/host-jwks.json"
cp "$scratch/host-public.pem" "$scratch/host-jwks.json" "$report/"
for variant in baseline previous candidate; do
  mkdir -p "$scratch/$variant/benchmarks"
  case "$variant" in
    baseline) git -C "$repo" archive "$baseline_sha" src | tar -x -C "$scratch/$variant" ;;
    previous) git -C "$repo" archive "$borrowed_sha" src | tar -x -C "$scratch/$variant" ;;
    candidate) cp -a "$repo/src" "$scratch/$variant/" ;;
  esac
  cp -a "$scratch/host/vendor" "$scratch/$variant/"
  cp "$scratch/host/composer.json" "$scratch/$variant/"
  (cd "$scratch/$variant" && composer dump-autoload --no-dev --classmap-authoritative --no-interaction) >> "$report/install.log" 2>&1
  cp "$repo/benchmarks/host-workload.php" "$scratch/$variant/benchmarks/"
  php -r 'file_put_contents($argv[1], str_repeat("release-stream-v1", 4096));' "$scratch/$variant/benchmarks/host-payload.bin"
  cp "$scratch/host-public.pem" "$scratch/host-jwks.json" "$scratch/$variant/benchmarks/"
done
mkdir -p "$scratch/candidate/tests/Smoke"
cp "$repo/tests/Smoke/persistent-runwire-host.php" "$scratch/candidate/tests/Smoke/"
cat > "$scratch/fpm.conf" <<'FPM'
[www]
pm = static
pm.max_children = 4
pm.max_requests = 0
catch_workers_output = yes
access.log = /dev/null
FPM
cat > "$scratch/opcache.ini" <<'INI'
opcache.enable=1
opcache.validate_timestamps=0
opcache.memory_consumption=128
opcache.jit=off
INI
if [[ -z ${HOST_TOOLS_IMAGE:-} ]]; then
  printf '%s\n' 'FROM nginx:1.30.5-alpine3.24' 'RUN apk add --no-cache bash curl wrk procps coreutils' > "$scratch/Dockerfile"
  docker build -t "$tools_image" "$scratch" > "$report/tools-build.log" 2>&1
fi
docker network create "$prefix" >/dev/null
# Use the same workers, network path and tmpfs for every variant. Separate pools
# produced a >2% false regression even with identical code in hosted A/A trials.
docker run -d --name "$prefix-fpm" --network "$prefix" --cpuset-cpus="${HOST_FPM_CPUS:-2,3}" \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m,mode=1777 \
  -v "$scratch/baseline:/app/baseline:ro" -v "$scratch/previous:/app/previous:ro" \
  -v "$scratch/candidate:/app/candidate:ro" -v "$scratch/fpm.conf:/usr/local/etc/php-fpm.d/zz-release.conf:ro" \
  -v "$scratch/opcache.ini:/usr/local/etc/php/conf.d/zz-release.ini:ro" "$php_image" > /dev/null
printf 'events {}\nhttp { access_log off;\nmap $arg_variant $epicrypt_script {\ndefault "";\n' > "$scratch/nginx.conf"
for variant in baseline previous candidate; do
  printf '%s /app/%s/benchmarks/host-workload.php;\n' "$variant" "$variant" >> "$scratch/nginx.conf"
done
printf '}\nserver { listen 8080; location / { include /etc/nginx/fastcgi_params; fastcgi_param SCRIPT_FILENAME $epicrypt_script; fastcgi_pass %s-fpm:9000; } }\n}\n' "$prefix" >> "$scratch/nginx.conf"
docker run -d --name "$prefix-proxy" --network "$prefix" --cpuset-cpus="${HOST_PROXY_CPUS:-0}" \
  -v "$scratch/nginx.conf:/etc/nginx/nginx.conf:ro" "$tools_image" > /dev/null
docker run -d --name "$prefix-client" --network "$prefix" --pid=host --cpuset-cpus="${HOST_CLIENT_CPUS:-1}" \
  -v "$repo/benchmarks:/benchmarks:ro" -v "$report:/report" --entrypoint sleep "$tools_image" infinity > /dev/null
docker image inspect "$php_image" "$tools_image" > "$report/images.json"
docker exec "$prefix-fpm" php -i > "$report/php-profile.txt"
docker info > "$report/docker-profile.txt"
printf 'FPM_CPUS=%s\nPROXY_CPUS=%s\nCLIENT_CPUS=%s\nSOAK_CPUS=%s\nWARMUP=%s\n' \
  "${HOST_FPM_CPUS:-2,3}" "${HOST_PROXY_CPUS:-0}" "${HOST_CLIENT_CPUS:-1}" "${HOST_SOAK_CPUS:-6}" \
  "${HOST_WARMUP_DURATION:-60s}" > "$report/deployment-profile.txt"
printf 'FPM_POOL=shared\nFPM_WORKERS=4\n' >> "$report/deployment-profile.txt"
lscpu >> "$report/deployment-profile.txt"
taskset -pc $$ >> "$report/deployment-profile.txt"
printf 'Shared FPM master affinity: ' >> "$report/deployment-profile.txt"
docker exec "$prefix-fpm" sh -c 'grep "^Cpus_allowed_list:" /proc/1/status' >> "$report/deployment-profile.txt"
cp "$scratch/fpm.conf" "$scratch/opcache.ini" "$scratch/nginx.conf" "$report/"
docker top "$prefix-fpm" > "$report/initial-workers.txt"
for variant in baseline previous candidate; do
  for attempt in {1..30}; do
    if docker exec "$prefix-client" curl -fsS "http://$prefix-proxy:8080/?variant=$variant&scenario=mixed" | grep -Fxq release-health-ok; then break; fi
    sleep 1
  done
  docker exec "$prefix-client" curl -fsS -D "/report/preflight-$variant.headers" \
    "http://$prefix-proxy:8080/?variant=$variant&scenario=mixed" | grep -Fxq release-health-ok
  tr -d '\r' < "$report/preflight-$variant.headers" | grep -Fixq "X-Epicrypt-Deployment: $variant"
done
(
  while true; do
    date -u +'%Y-%m-%dT%H:%M:%SZ'
    docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}} {{.PIDs}}' \
      "$prefix-client" "$prefix-proxy" "$prefix-fpm"
  done
) > "$report/resources.log" 2>&1 &
sampler=$!
for mode in unbound borrowed; do
  if [[ $mode == unbound ]]; then base=baseline; bound=0; else base=previous; bound=1; fi
  shared_pid=$(docker inspect --format '{{.State.Pid}}' "$prefix-fpm")
  for concurrency in ${HOST_CONCURRENCIES:-1 4 8}; do
    # Readiness and warmup precede each measured comparison, including the borrowed path.
    for variant in "$base" candidate; do
      docker exec -e HOST_EXPECTED_BODY=release-health-ok "$prefix-client" wrk -t1 -c"$concurrency" -d"${HOST_WARMUP_DURATION:-60s}" \
        -s /benchmarks/host-rpm-validate.lua "http://$prefix-proxy:8080/?variant=$variant&scenario=mixed&bound=$bound" > "$report/warm-$mode-c$concurrency-$variant.log"
    done
    docker exec -e HOST_BASE_PID="$shared_pid" -e HOST_CANDIDATE_PID="$shared_pid" \
      -e HOST_ROUNDS="${HOST_ROUNDS:-3}" -e HOST_DURATION="${HOST_DURATION:-60s}" \
      -e HOST_THREADS=1 -e HOST_CONNECTIONS="$concurrency" -e HOST_EXPECTED_BODY=release-health-ok \
      -e HOST_MAX_RSS_KIB="${HOST_MAX_RSS_KIB:-262144}" -e HOST_REPORT="/report/$mode-c$concurrency.tsv" \
      "$prefix-client" bash /benchmarks/host-rpm-compare.sh \
      "http://$prefix-proxy:8080/?variant=$base&scenario=mixed&bound=$bound" \
      "http://$prefix-proxy:8080/?variant=candidate&scenario=mixed&bound=$bound" | tee "$report/$mode-c$concurrency.log"
  done
done
docker run -d --name "$prefix-soak" --cpuset-cpus="${HOST_SOAK_CPUS:-6}" \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m,mode=1777 \
  -v "$scratch/candidate:/app:ro" -e EPICRYPT_HOST_SOAK_SECONDS="${HOST_SOAK_SECONDS:-300}" \
  --entrypoint php "$php_image" /app/tests/Smoke/persistent-runwire-host.php >/dev/null
soak_pid=$(docker inspect --format '{{.State.Pid}}' "$prefix-soak")
peak=0
printf 'elapsed_sample\trss_kib\n' > "$report/persistent-rss.tsv"
sample=0
while [[ $(docker inspect --format '{{.State.Running}}' "$prefix-soak") == true ]]; do
  rss=$(docker exec "$prefix-client" ps -p "$soak_pid" -o rss= | tr -d ' ') || rss=''
  if [[ $rss =~ ^[0-9]+$ ]]; then
    ((rss > peak)) && peak=$rss
    printf '%d\t%d\n' "$sample" "$rss" >> "$report/persistent-rss.tsv"
    ((sample+=1))
  fi
  sleep 0.25
done
exit_code=$(docker wait "$prefix-soak")
docker logs "$prefix-soak" > "$report/persistent-soak.json" 2>&1
[[ $exit_code == 0 ]] && ((peak > 0 && peak <= ${HOST_MAX_RSS_KIB:-262144})) || { echo 'Persistent host soak/RSS guard failed' >&2; exit 1; }
printf '%d\n' "$peak" > "$report/persistent-peak-rss-kib"
old_pid=$(docker inspect --format '{{.State.Pid}}' "$prefix-fpm")
docker restart "$prefix-fpm" >/dev/null
new_pid=$(docker inspect --format '{{.State.Pid}}' "$prefix-fpm")
[[ $new_pid != "$old_pid" ]] || { echo 'FPM replacement did not change host PID' >&2; exit 1; }
for attempt in {1..30}; do
  if docker exec "$prefix-client" curl -fsS "http://$prefix-proxy:8080/?variant=candidate&scenario=mixed&bound=1" | grep -Fxq release-health-ok; then break; fi
  sleep 1
done
docker exec "$prefix-client" curl -fsS "http://$prefix-proxy:8080/?variant=candidate&scenario=mixed&bound=1" | grep -Fxq release-health-ok
printf '%s -> %s\n' "$old_pid" "$new_pid" > "$report/worker-replacement.txt"
docker logs "$prefix-fpm" > "$report/fpm.log" 2>&1
echo "Docker host evidence: $report"
