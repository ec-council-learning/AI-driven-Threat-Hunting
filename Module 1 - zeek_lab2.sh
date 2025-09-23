#!/usr/bin/env bash
# zeek_lab.sh
# Persistent lab traffic generator for Zeek logs (benign)
#
# Usage: sudo ./zeek_lab.sh
# NOTE: run only in a controlled lab environment. Do not target external systems.

set -euo pipefail
IFS=$'\n\t'

# Config - change if needed
TARGETS=( "192.168.56.3" "192.168.56.5" )
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

# how long to sleep between cycles (randomized between MIN and MAX seconds)
SLEEP_MIN=5
SLEEP_MAX=15

# helper: log
log() {
  local ts msg
  ts=$(date --iso-8601=seconds)
  msg="$*"
  echo "${ts} ${msg}" | tee -a "${LOGFILE}"
}

# trap for graceful shutdown logging
graceful_shutdown() {
  log "Received stop signal — exiting."
  exit 0
}
trap graceful_shutdown SIGINT SIGTERM

# helper: random element
rand_elem() {
  local arr=("${!1}")
  echo "${arr[RANDOM % ${#arr[@]}]}"
}

# helper: random domain like a1b2c3.<tld>
gen_random_domain() {
  local rnd=$(head -c 6 /dev/urandom | base64 | tr -dc 'a-z0-9' | cut -c1-6)
  local tld=$(rand_elem DNS_TLD_POOL[@])
  echo "${rnd}.example-${tld}"
}

# Send DNS queries using dig (one-shot)
do_dns_queries() {
  for i in 1 2 3; do
    local d
    d="$(gen_random_domain)"
    log "DNS query: ${d}"
    # query local resolver; keep short timeout
    dig +noall +answer +time=3 "${d}" @127.0.0.53 >/dev/null 2>&1 || true
    sleep 0.5
  done
}

# HTTP beacon: curl GET random path to each target
do_http_beacon() {
  local target="$1"
  for i in 1 2; do
    local ua path port
    ua=$(rand_elem USERAGENTS[@])
    path="/.well-known/$(head -c4 /dev/urandom | base64 | tr -dc 'a-z0-9' | cut -c1-6)"
    port="${TCP_PORT_POOL[$((RANDOM % ${#TCP_PORT_POOL[@]}))]}"
    log "HTTP beacon -> ${target}:${port}${path} (UA=${ua})"
    curl --max-time 6 -s -o /dev/null -A "${ua}" "http://${target}:${port}${path}" >/dev/null 2>&1 || true
    sleep 0.3
  done
}

# TCP connect (short-lived) using nc with timeout
do_tcp_connect() {
  local target="$1"
  local port="${TCP_PORT_POOL[$((RANDOM % ${#TCP_PORT_POOL[@]}))]}"
  log "TCP connect -> ${target}:${port}"
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
    sudo hping3 -S -p "${port}" -c 1 "${target}" >/dev/null 2>&1 || true
  fi
}

# one iteration
run_one_iteration() {
  do_dns_queries
  for t in "${TARGETS[@]}"; do
    do_http_beacon "${t}"
    do_tcp_connect "${t}"
    do_udp_send "${t}"
    do_syn_probe "${t}"
  done
}

# ensure logfile exists and is writable
sudo touch "${LOGFILE}" 2>/dev/null || true
sudo chown "$(id -u):$(id -g)" "${LOGFILE}" 2>/dev/null || true

log "Starting persistent Zeek lab traffic generator (press Ctrl+C to stop). Targets: ${TARGETS[*]}"

# main loop: run forever until stopped
while true; do
  run_one_iteration
  # randomized small sleep to avoid perfectly periodic traffic
  sleep_seconds=$(( SLEEP_MIN + RANDOM % ( (SLEEP_MAX - SLEEP_MIN) + 1 ) ))
  log "Sleeping ${sleep_seconds}s before next iteration..."
  sleep "${sleep_seconds}"
done

