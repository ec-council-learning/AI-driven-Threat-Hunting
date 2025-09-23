#!/usr/bin/env bash
# zeek_lab_traffic.sh
# Lab traffic generator for Zeek logs (benign)
#
# Usage: sudo ./zeek_lab_traffic.sh
# NOTE: run only in a controlled lab environment. Do not target external systems.

set -euo pipefail
IFS=$'\n\t'

# Config - change if needed
KALI_INTERFACE=""              # optional: e.g. "eth0" if you need to bind/outgoing
TARGETS=( "192.168.56.3" "192.168.56.5" )
CYCLE_MINUTES=30
CYCLES=20                       # 20 * 30min = 600 minutes = 10 hours
LOGFILE="/var/log/zeek-lab-traffic.log"
USERAGENTS=( \
  "ZeekSim/1.0" \
  "Mozilla/5.0 (X11; Kali) ZeekTest" \
  "curl/7.XX ZeekBeacon" \
)
# uncommon ports to try for TCP/UDP (non-destructive)
TCP_PORT_POOL=( 4444 5555 8081 9001 10022 )
UDP_PORT_POOL=( 5355 12345 33434 9999 )
DNS_TLD_POOL=( "com" "net" "info" "dev" "lab" )

# helper: log
log() {
  local t ts msg
  ts=$(date --iso-8601=seconds)
  msg="$*"
  echo "${ts} ${msg}" | tee -a "${LOGFILE}"
}

# helper: random element
rand_elem() {
  local arr=("${!1}")
  echo "${arr[RANDOM % ${#arr[@]}]}"
}

# helper: random domain like a1b2c3.<tld>
gen_random_domain() {
  local rnd=$(head -c 6 /dev/urandom | base64 | tr -dc 'a-z0-9' | cut -c1-6)
  local tld=$(rand_elem DNS_TLD_POOL[@])
  echo "${rnd}.example-${tld}"   # example- added so it's safe; won't collide with real popular domains
}

# Send DNS queries using dig (one-shot)
do_dns_queries() {
  for i in 1 2 3; do
    d="$(gen_random_domain)"
    # use system resolver; add +short to avoid noisy output
    log "DNS query: ${d}"
    dig +noall +answer +time=3 "${d}" @127.0.0.53 >/dev/null 2>&1 || true
    sleep 0.5
  done
}

# HTTP beacon: curl GET random path to each target
do_http_beacon() {
  local target="$1"
  for i in 1 2; do
    local ua=$(rand_elem USERAGENTS[@])
    local path="/.well-known/$(head -c4 /dev/urandom | base64 | tr -dc 'a-z0-9' | cut -c1-6)"
    # choose http or https by port guess: try HTTP on 80/8081 etc.
    # use --max-time to avoid hanging
    log "HTTP beacon -> ${target}${path} (UA=${ua})"
    curl --max-time 6 -s -o /dev/null -A "${ua}" "http://${target}:${TCP_PORT_POOL[$((RANDOM % ${#TCP_PORT_POOL[@]}))]}${path}" >/dev/null 2>&1 || true
    sleep 0.5
  done
}

# TCP connect (short-lived) using nc with timeout
do_tcp_connect() {
  local target="$1"
  local port="${TCP_PORT_POOL[$((RANDOM % ${#TCP_PORT_POOL[@]}))]}"
  log "TCP connect -> ${target}:${port}"
  # Use timeout of 3 seconds to avoid hangs
  timeout 3 nc -w 2 "${target}" "${port}" < /dev/null >/dev/null 2>&1 || true
}

# UDP packet (single) using nc -u
do_udp_send() {
  local target="$1"
  local port="${UDP_PORT_POOL[$((RANDOM % ${#UDP_PORT_POOL[@]}))]}"
  log "UDP send -> ${target}:${port}"
  printf "zeek-lab-pkt\n" | timeout 2 nc -u -w 1 "${target}" "${port}" >/dev/null 2>&1 || true
}

# Single SYN probe using hping3 (non-flood)
do_syn_probe() {
  local target="$1"
  local port="${TCP_PORT_POOL[$((RANDOM % ${#TCP_PORT_POOL[@]}))]}"
  if command -v hping3 >/dev/null 2>&1; then
    log "SYN probe -> ${target}:${port}"
    # send a single SYN (-S) and exit (-c 1), quiet
    sudo hping3 -S -p "${port}" -c 1 "${target}" >/dev/null 2>&1 || true
  fi
}

# single cycle
run_cycle() {
  local iter="$1"
  log "===== cycle ${iter} start ====="
  do_dns_queries
  for t in "${TARGETS[@]}"; do
    do_http_beacon "${t}"
    do_tcp_connect "${t}"
    do_udp_send "${t}"
    do_syn_probe "${t}"
  done
  log "===== cycle ${iter} end ====="
}

main() {
  # ensure logfile exists and writable
  sudo touch "${LOGFILE}" 2>/dev/null || true
  sudo chown "$(id -u):$(id -g)" "${LOGFILE}" 2>/dev/null || true

  log "Starting Zeek lab traffic generator. cycles=${CYCLES}, interval=${CYCLE_MINUTES}m"
  for i in $(seq 1 "${CYCLES}"); do
    run_cycle "${i}"
    if [ "${i}" -lt "${CYCLES}" ]; then
      log "Sleeping for ${CYCLE_MINUTES} minutes..."
      sleep $(( CYCLE_MINUTES * 60 ))
    fi
  done
  log "Completed all cycles. Exiting."
}

main "$@"
