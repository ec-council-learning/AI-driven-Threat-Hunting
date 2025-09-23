#!/usr/bin/env bash
# zeek_dns_generator.sh
# DNS traffic generator for lab (benign, for Zeek log population and ML experiments)
# Usage: sudo /usr/local/bin/zeek_dns_generator.sh

set -euo pipefail
IFS=$'\n\t'

LOGFILE="/var/log/zeek-dns-gen.log"

# DNS servers to query (lab + public)
DNS_SERVERS=( \
  "192.168.56.3" \
  "192.168.56.5" \
  "192.168.56.1" \
  "192.168.56.254" \
  "8.8.8.8" \
  "1.1.1.1" \
  "9.9.9.9" \
  "208.67.222.222" \
  "84.200.69.80" \
)

# Valid domains to mix in
VALID_DOMAINS=( \
  "bin.com" \
  "google.com" \
  "github.com" \
  "microsoft.com" \
  "openai.com" \
  "cloudflare.com" \
  "GY4CANRVEA3TEIBWGUQDMOJAG4ZSANRREA3GIIBWGEQDMYZAGY4SANRTEA3DSIBWMYQDONJAG4ZSANRUEA3GMIBWMQQDMMJAGY4SANTF.org"\
  "NTYgNjUgNzIgNzkgNGMgNmYgNmUgNjcgNDQgNmYgNmQgNjEgNjkgNmUgNGUgNjEgNmQgNjU.net"
)

# Query types
QTYPES=( "A" "AAAA" "TXT" "MX" "NS" "ANY" )

# Intensity
QUERIES_PER_ITER=8
SLEEP_MIN=2
SLEEP_MAX=6
BEACON_PROB=0.15
LARGE_TXT_SIZE=180

log() {
  local ts msg
  ts=$(date --iso-8601=seconds)
  msg="$*"
  echo "${ts} ${msg}" | tee -a "${LOGFILE}"
}

trap 'log "SIGINT/SIGTERM received — stopping."; exit 0' SIGINT SIGTERM

rand_range() { # min max
  local min=$1 max=$2
  echo $(( min + RANDOM % ( (max - min) + 1 ) ))
}
rand_elem() {
  local arr=("${!1}")
  echo "${arr[RANDOM % ${#arr[@]}]}"
}

# Random high-entropy label (len 6–18)
gen_label() {
  local len=$((6 + RANDOM % 13))
  tr -dc 'a-z0-9' </dev/urandom | head -c "${len}"
}

# Very long label (>63)
gen_long_label() {
  tr -dc 'a-z0-9' </dev/urandom | head -c 80
}

# Many-label domain
gen_many_labels() {
  local n=$((10 + RANDOM % 8))
  local out=""
  for _ in $(seq 1 "$n"); do
    out+="$(gen_label)."
  done
  echo "${out}google.com"
}

# Numeric-only domain  (FIXED)
gen_numeric_domain() {
  local len=$((4 + RANDOM % 8))
  echo "$(tr -dc '0-9' </dev/urandom | head -c "${len}").microsoft.com"
}

# Single-character label chain
gen_single_char_chain() {
  local n=$((6 + RANDOM % 8))
  local out=""
  for _ in $(seq 1 "$n"); do
    out+="$(tr -dc 'a-z' </dev/urandom | head -c1)."
  done
  echo "${out}malicious.net"
}

# Large TXT payload (sample)
gen_large_txt() {
  head -c "${LARGE_TXT_SIZE}" /dev/urandom | base64 | tr -d '\n' | sed 's/.\{250\}/&\n/g' | head -n1
}

# Build candidate list
build_domains() {
  local domains=()
  domains+=( "$(rand_elem VALID_DOMAINS[@])" )
  domains+=( "$(rand_elem VALID_DOMAINS[@])" )
  domains+=( "$(gen_label).$(rand_elem VALID_DOMAINS[@])" )
  domains+=( "$(gen_label).$(rand_elem VALID_DOMAINS[@])" )
  domains+=( "$(gen_long_label).example.com" )
  domains+=( "$(gen_many_labels)" )
  domains+=( "$(gen_numeric_domain)" )
  domains+=( "$(gen_single_char_chain)" )
  echo "${domains[@]}"
}

# Perform a single query using dig (SIMPLIFIED: 3 params)
do_query() {
  local server="$1" name="$2" qtype="$3"
  local dig_cmd=(dig +time=3 +tries=1 +noall +nostats)
  if [ $(( RANDOM % 10 )) -lt 2 ]; then
    dig_cmd+=( +dnssec )
  fi
  dig_cmd+=( "${qtype}" "@${server}" "${name}" )
  log "Query -> server=${server} name=${name} type=${qtype}"
  "${dig_cmd[@]}" >/dev/null 2>&1 || true
}

# Beacon pattern
do_beacon() {
  local name="$1" qtype="$2" repeats="$3"
  for i in $(seq 1 "${repeats}"); do
    local server
    server=$(rand_elem DNS_SERVERS[@])
    log "Beacon-query (${i}/${repeats}) -> ${server} ${name} ${qtype}"
    do_query "${server}" "${name}" "${qtype}"
    sleep 0.4
  done
}

log "Starting DNS generator. Servers: ${DNS_SERVERS[*]}. Press Ctrl+C to stop."
sudo touch "${LOGFILE}" 2>/dev/null || true
sudo chown "$(id -u):$(id -g)" "${LOGFILE}" 2>/dev/null || true

while true; do
  IFS=' ' read -r -a CANDIDATES <<< "$(build_domains)"

  for _ in $(seq 1 "${QUERIES_PER_ITER}"); do
    server=$(rand_elem DNS_SERVERS[@])

    if [ $((RANDOM % 100)) -lt 60 ]; then
      name="${CANDIDATES[RANDOM % ${#CANDIDATES[@]}]}"
    else
      name="$(gen_label).$(rand_elem VALID_DOMAINS[@])"
    fi

    qtype=$(rand_elem QTYPES[@])

    if [ "${qtype}" = "TXT" ] && [ $((RANDOM % 100)) -lt 40 ]; then
      payload="$(gen_large_txt)"
      log "Large TXT payload (sample) length=${#payload}"
      do_query "${server}" "${name}" "TXT"
    else
      do_query "${server}" "${name}" "${qtype}"
    fi

    # Beacon (repeated queries)
    awk "BEGIN{srand(); print (rand() < ${BEACON_PROB}) }" | grep -q 1 && {
      reps=$((2 + RANDOM % 3))
      do_beacon "${name}" "${qtype}" "${reps}"
    }

    # Short NXDOMAIN-ish burst
    if [ $((RANDOM % 100)) -lt 8 ]; then
      for _ in 1 2 3; do
        randn="$(gen_label).$(gen_label).$(rand_elem VALID_DOMAINS[@])"
        do_query "$(rand_elem DNS_SERVERS[@])" "${randn}" "A"
        sleep 0.2
      done
    fi

    sleep 0.25
  done

  s=$(rand_range "${SLEEP_MIN}" "${SLEEP_MAX}")
  log "Iteration complete — sleeping ${s}s"
  sleep "${s}"
done
