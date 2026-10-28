"""0B.5: per-class edge measurement (precision/recall/FP/latency/throughput).

Plan v7.5 0B.5: "Report precision, recall/false negatives, false-positive
rate and latency/throughput per class and placement. Include poor results.
No broad protection claim without these numbers."

The module sends every labeled corpus entry (src/edge_corpus.py) to a
running shipped-node container, records the observed status and latency,
and summarises:

  - per attack class: total / blocked / missed ids / recall / latency
  - safe traffic: total / blocked ids / false-positive rate / latency
  - per placement: attacks seen and blocked by each mechanism
  - overall precision and recall

The renderer emits the markdown table published in
docs/guide/measurement.md; the docker tests re-measure the node and
compare the published table against the live numbers so the report can
never drift from the engine behaviour.

The probes use raw sockets for the same reason as the corpus tests:
requests re-encodes unsafe URL characters, which would silently rewrite
the measured payload representation.
"""

import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from statistics import median
from typing import List

from src.edge_corpus import EDGE_CORPUS, Entry

# Sequential safe requests used for the throughput figure. Deliberately
# small: this is a per-commit sanity figure, not a load test.
THROUGHPUT_REQUESTS = 30


@dataclass
class Observation:
    entry_id: str
    attack_class: str
    placement: str
    expected_status: int
    status: int
    latency_ms: float


def _send(port: int, entry: Entry) -> Observation:
    """Send the request as LITERAL BYTES and return status plus latency."""
    method, path, headers, body = entry.spec
    request = f"{method} {path} HTTP/1.1\r\nHost: nginx-node-1\r\nConnection: close\r\n"
    for name, value in headers.items():
        request += f"{name}: {value}\r\n"
    if body:
        request += f"Content-Length: {len(body.encode('utf-8'))}\r\n"
    request += "\r\n"
    if body:
        request += body

    started = time.perf_counter()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.sendall(request.encode("utf-8"))
        response = b""
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
    latency_ms = (time.perf_counter() - started) * 1000.0

    head = response.split(b"\r\n", 1)[0].decode("latin-1")
    if not head.startswith("HTTP/"):
        raise RuntimeError(f"node returned no valid HTTP head for {entry.rule_id}: {head!r}")
    status = int(head.split(" ")[1])
    return Observation(
        entry_id=entry.rule_id,
        attack_class=entry.attack_class,
        placement=entry.placement,
        expected_status=entry.expected_status,
        status=status,
        latency_ms=latency_ms,
    )


def _throughput(port: int) -> float:
    started = time.perf_counter()
    for _ in range(THROUGHPUT_REQUESTS):
        with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
            conn.sendall(b"GET / HTTP/1.1\r\nHost: nginx-node-1\r\nConnection: close\r\n\r\n")
            conn.recv(4096)
    elapsed = time.perf_counter() - started
    return THROUGHPUT_REQUESTS / elapsed if elapsed > 0 else 0.0


def _p95(values: List[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round(0.95 * (len(ordered) - 1)))
    return ordered[index]


def run_measurement(port: int) -> List[Observation]:
    """Measure every corpus entry against the node on 127.0.0.1:port."""
    return [_send(port, entry) for entry in EDGE_CORPUS.entries]


def summarize(observations: List[Observation]) -> dict:
    """Per-class and per-placement decision metrics from raw observations."""
    attacks = [o for o in observations if o.attack_class != "legitimate"]
    safe = [o for o in observations if o.attack_class == "legitimate"]

    classes = sorted({o.attack_class for o in attacks})
    per_class = {}
    blocked_total = 0
    for attack_class in classes:
        members = [o for o in attacks if o.attack_class == attack_class]
        blocked = [o for o in members if o.status == o.expected_status]
        missed = [o for o in members if o.status != o.expected_status]
        blocked_total += len(blocked)
        per_class[attack_class] = {
            "total": len(members),
            "blocked": len(blocked),
            "missed": [o.entry_id for o in missed],
            "recall": len(blocked) / len(members) if members else 0.0,
            "latency_ms": {
                "p50": median([o.latency_ms for o in blocked] or [0.0]),
                "p95": _p95([o.latency_ms for o in blocked]),
            },
        }

    safe_blocked = [o for o in safe if o.status != o.expected_status]
    per_placement = {}
    for placement in sorted({o.placement for o in attacks}):
        members = [o for o in attacks if o.placement == placement]
        per_placement[placement] = {
            "attacks": len(members),
            "blocked": len([o for o in members if o.status == o.expected_status]),
        }

    safe_latencies = [o.latency_ms for o in safe if o.status == o.expected_status]
    attack_latencies = [o.latency_ms for o in attacks if o.status == o.expected_status]

    return {
        "counts": {"attacks": len(attacks), "safe": len(safe)},
        "per_class": per_class,
        "per_placement": per_placement,
        "recall": blocked_total / len(attacks) if attacks else 0.0,
        "precision": (
            blocked_total / (blocked_total + len(safe_blocked))
            if (blocked_total + len(safe_blocked)) else 0.0
        ),
        "safe": {
            "total": len(safe),
            "blocked": len(safe_blocked),
            "blocked_ids": [o.entry_id for o in safe_blocked],
            "false_positive_rate": (
                len(safe_blocked) / len(safe) if safe else 0.0
            ),
            "latency_ms": {
                "p50": median(safe_latencies or [0.0]),
                "p95": _p95(safe_latencies),
            },
        },
        "latency_ms": {
            "p50": median(attack_latencies or [0.0]),
            "p95": _p95(attack_latencies),
        },
    }


def render_report(observations: List[Observation], environment: str,
                  throughput_rps: float = 0.0) -> str:
    """Render the measured numbers as the published report table."""
    report = summarize(observations)
    lines = []
    lines.append("| class | total | blocked | missed | recall | latency p50/p95 (ms) |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for attack_class, metrics in report["per_class"].items():
        missed = ", ".join(metrics["missed"]) if metrics["missed"] else "none"
        lat = metrics["latency_ms"]
        lines.append(
            f"| {attack_class} | {metrics['total']} | {metrics['blocked']} "
            f"| {missed} | {metrics['recall']:.0%} "
            f"| {lat['p50']:.1f} / {lat['p95']:.1f} |"
        )
    safe = report["safe"]
    lines.append(
        f"| legitimate (safe) | {safe['total']} | {safe['blocked']} "
        f"| {', '.join(safe['blocked_ids']) if safe['blocked_ids'] else 'none'} "
        f"| false positive rate {safe['false_positive_rate']:.0%} "
        f"| {safe['latency_ms']['p50']:.1f} / {safe['latency_ms']['p95']:.1f} |"
    )
    lines.append("")
    lines.append(f"- overall recall: {report['recall']:.0%} "
                 f"({report['counts']['attacks']} labeled attacks)")
    lines.append(f"- overall precision: {report['precision']:.0%}")
    lines.append("- per placement: " + ", ".join(
        f"{placement} {stats['blocked']}/{stats['attacks']} blocked"
        for placement, stats in report["per_placement"].items()
    ))
    lines.append(f"- environment: {environment}")
    if throughput_rps:
        lines.append(f"- sequential throughput on GET /: {throughput_rps:.1f} req/s "
                     f"({THROUGHPUT_REQUESTS} requests)")
    lines.append("- limitations: the corpus is a small, hand-labeled set "
                 "({} attacks / {} safe requests); it pins known regressions "
                 "and measured bypasses, it is NOT a broad protection claim; "
                 "latency and throughput are one-container figures from the "
                 "measurement environment, not production numbers.".format(
                     report["counts"]["attacks"], report["counts"]["safe"]))
    return "\n".join(lines)


def spin_up_node():
    """Context manager: a throwaway container running the SHIPPED node
    image with the repository's real configuration (compose-identical
    mounts), yielding the host port it listens on."""
    from contextlib import contextmanager
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    node1_dir = repo_root / "docker" / "nginx-node-1"

    @contextmanager
    def _run():
        container = f"waf-measure-{uuid.uuid4().hex[:12]}"
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        build = subprocess.run(
            ["docker", "build", "-q", "-t", "waf-corpus-node", str(node1_dir)],
            capture_output=True, text=True, timeout=900,
        )
        if build.returncode != 0:
            raise RuntimeError(f"corpus node image failed to build: {build.stderr.strip()[:200]}")

        mounts = [
            "-v", f"{node1_dir / 'nginx.conf'}:/etc/nginx/templates/nginx.conf.template:ro",
            "-v", f"{node1_dir / 'default.conf'}:/etc/nginx/conf.d/waf-node.conf:ro",
            "-v", f"{node1_dir / 'api.js'}:/etc/nginx/api.js:ro",
            "-v", f"{repo_root / 'docker' / 'shared' / 'waf-rules' / 'basic.conf'}:/etc/nginx/waf-rules/basic.conf:ro",
        ]
        try:
            proc = subprocess.run(
                ["docker", "run", "-d", "--rm", "--name", container,
                 "-p", f"127.0.0.1:{port}:80", *mounts, "waf-corpus-node"],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"corpus nginx failed to start: {proc.stderr.strip()[:200]}")
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                # Full HTTP round trip: on Docker Desktop the port proxy
                # accepts TCP connects before nginx is listening, so a bare
                # connect proves nothing.
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                        conn.sendall(b"GET / HTTP/1.1\r\nHost: nginx-node-1\r\nConnection: close\r\n\r\n")
                        head = conn.recv(4096).split(b"\r\n", 1)[0].decode("latin-1")
                    if head.startswith("HTTP/"):
                        break
                except OSError:
                    pass
                time.sleep(0.4)
            else:
                raise RuntimeError("corpus nginx never became ready")
            yield port
        finally:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=30)

    return _run()
