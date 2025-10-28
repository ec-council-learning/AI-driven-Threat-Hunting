#!/usr/bin/env python3
"""
benign beacon generator for lab exercises.

- Sends periodic HTTP GETs to a target (Windows Server at 192.168.56.3 by default).
- Sends periodic DNS queries to a configured DNS resolver (192.168.56.3 by default with dig).
- Can generate DGA-like subdomains for DNS requests (optional) to emulate varied queries.
- Runs HTTP and DNS beacons concurrently (threads).
- Logs to console and to a CSV file (timestamp, type, target, status, extra).

Requirements:
- Python 3.7+
- requests library (pip install requests)
- dig (dnsutils) available on Kali (you already tested it)

Usage example:
    python3 beacon_lab.py --target-ip 192.168.56.3 --resolver 192.168.56.3 --http-interval 60 --dns-interval 60 --rounds 100
"""
import argparse
import csv
import datetime
import random
import subprocess
import threading
import time
import sys
import os
import socket

try:
    import requests
except Exception:
    print("Missing 'requests' python package. Install with: pip3 install requests")
    sys.exit(1)

CSV_FIELDS = ["timestamp","type","seq","target","detail","status","latency_ms"]

def now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"

def write_csv_row(csv_path, row):
    write_header = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            w.writeheader()
        w.writerow(row)

def http_beacon_worker(target_ip, port, interval, jitter, rounds, csv_path, path="/"):
    """Periodic HTTP GETs to target_ip:port"""
    url = f"http://{target_ip}:{port}{path}"
    for i in range(1, rounds+1):
        start = time.time()
        try:
            r = requests.get(url, timeout=5)
            latency = int((time.time() - start) * 1000)
            status = r.status_code
            detail = f"GET {url}"
            print(f"[HTTP] #{i}/{rounds} -> {url} status={status} latency={latency}ms")
            row = {
                "timestamp": now_iso(),
                "type": "http",
                "seq": i,
                "target": url,
                "detail": detail,
                "status": status,
                "latency_ms": latency
            }
        except Exception as e:
            latency = int((time.time() - start) * 1000)
            print(f"[HTTP] #{i}/{rounds} -> {url} ERROR: {e}")
            row = {
                "timestamp": now_iso(),
                "type": "http",
                "seq": i,
                "target": url,
                "detail": f"error:{e}",
                "status": "error",
                "latency_ms": latency
            }
        write_csv_row(csv_path, row)
        # sleep with jitter
        sleep = max(0.5, interval + random.uniform(-jitter, jitter))
        time.sleep(sleep)

def dns_query(domain, resolver, timeout=5):
    """Run dig to the resolver for the domain, return stdout and returncode."""
    # Use dig with explicit resolver @IP
    try:
        # +time= sets timeout for each attempt (seconds)
        proc = subprocess.run(["dig", f"@{resolver}", domain, "+short"], capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip()
    except subprocess.TimeoutExpired as e:
        return 2, ""  # special code for timeout
    except FileNotFoundError:
        raise RuntimeError("dig not found. Install dnsutils on Kali.")

def dns_beacon_worker(resolver, domain_template, use_dga, interval, jitter, rounds, csv_path):
    """
    Periodic DNS queries using 'dig'.
    domain_template can include '{i}' to insert sequence number.
    If use_dga True => generate pseudo-random subdomains.
    """
    for i in range(1, rounds+1):
        if use_dga:
            # simple DGA-like generator: hex-based short string + counter
            label = f"{random.getrandbits(32):08x}"
            domain = f"{label}.{domain_template}"
        else:
            if "{i}" in domain_template:
                domain = domain_template.format(i=i)
            else:
                domain = domain_template

        start = time.time()
        try:
            rc, out = dns_query(domain, resolver)
            latency = int((time.time() - start) * 1000)
            status = "ok" if rc == 0 else f"rc={rc}"
            detail = out if out else "<no-answer>"
            print(f"[DNS] #{i}/{rounds} -> {domain} resolver={resolver} rc={rc} latency={latency}ms")
            row = {
                "timestamp": now_iso(),
                "type": "dns",
                "seq": i,
                "target": domain,
                "detail": detail,
                "status": status,
                "latency_ms": latency
            }
        except Exception as e:
            latency = int((time.time() - start) * 1000)
            print(f"[DNS] #{i}/{rounds} -> {domain} ERROR: {e}")
            row = {
                "timestamp": now_iso(),
                "type": "dns",
                "seq": i,
                "target": domain,
                "detail": f"error:{e}",
                "status": "error",
                "latency_ms": latency
            }
        write_csv_row(csv_path, row)
        sleep = max(0.2, interval + random.uniform(-jitter, jitter))
        time.sleep(sleep)

def main():
    parser = argparse.ArgumentParser(description="Benign beacon generator for lab (HTTP + DNS).")
    parser.add_argument("--target-ip", default="192.168.56.3", help="HTTP target IP (Windows server)")
    parser.add_argument("--http-port", type=int, default=8000, help="HTTP port on target")
    parser.add_argument("--http-interval", type=float, default=60.0, help="HTTP beacon interval (seconds)")
    parser.add_argument("--http-jitter", type=float, default=5.0, help="HTTP jitter (+/- seconds)")
    parser.add_argument("--dns-resolver", default="192.168.56.3", help="DNS resolver to query (Windows server IP)")
    parser.add_argument("--dns-domain", default="example.lab", help="Domain template for DNS queries (use {i} for sequence number)")
    parser.add_argument("--dns-interval", type=float, default=60.0, help="DNS beacon interval (seconds)")
    parser.add_argument("--dns-jitter", type=float, default=3.0, help="DNS jitter (+/- seconds)")
    parser.add_argument("--dga", action="store_true", help="Generate DGA-like random subdomains for DNS queries")
    parser.add_argument("--rounds", type=int, default=100, help="Number of rounds for each beacon")
    parser.add_argument("--csv", default="beacon_log.csv", help="CSV file to write logs")
    args = parser.parse_args()

    print("Beacon lab starting with parameters:")
    print(args)

    # quick local connectivity tests
    try:
        socket.create_connection((args.target_ip, args.http_port), timeout=3).close()
        print(f"HTTP target {args.target_ip}:{args.http_port} reachable")
    except Exception as e:
        print(f"Warning: HTTP target reachability test failed: {e}")

    # Try simple UDP/TCP connectivity to resolver port 53 - optional
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b"", (args.dns_resolver, 53))
        s.close()
        print(f"DNS resolver {args.dns_resolver}:53 reachable (UDP probe attempted)")
    except Exception:
        print("DNS resolver UDP probe failed (this is not fatal if resolver is different)")

    # Start threads
    t_http = threading.Thread(target=http_beacon_worker, args=(args.target_ip, args.http_port, args.http_interval, args.http_jitter, args.rounds, args.csv), daemon=True)
    t_dns = threading.Thread(target=dns_beacon_worker, args=(args.dns_resolver, args.dns_domain, args.dga, args.dns_interval, args.dns_jitter, args.rounds, args.csv), daemon=True)

    try:
        t_http.start()
        t_dns.start()
        # Wait until both complete
        while t_http.is_alive() or t_dns.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("User interrupted. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
