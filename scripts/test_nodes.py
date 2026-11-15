"""Test stage: coarse TCP-reachability filter with latency measurement.

For every node we try a plain TCP connect to server:port (3 s timeout,
2 attempts per node, ~150 concurrent worker threads). Nodes whose port
answers are kept and annotated with their connection latency in ms;
everything else is dropped.

This is intentionally coarse — many free nodes sit behind CDNs or only
accept TLS/HTTP traffic on the port, so a successful TCP handshake is
already a strong signal. Fine-grained selection happens client-side via
the url-test "AUTO" group in the generated Clash config.

Never raises; unreachable hosts simply drop out.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from common import TCP_ATTEMPTS, TCP_TIMEOUT, TCP_WORKERS, log


def _tcp_probe(host: str, port: int) -> float | None:
    """Return latency in ms for one connect attempt, or None on failure."""
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return (time.perf_counter() - start) * 1000.0
    except (OSError, ValueError, UnicodeError):
        return None


def test_node(node: dict) -> dict | None:
    """Probe one node; returns the node with 'latency' set, or None."""
    host = str(node.get("server", "")).strip()
    port = node.get("port")
    if not host or not isinstance(port, int):
        return None
    # hysteresis: two attempts, keep the best successful latency
    best: float | None = None
    for _ in range(TCP_ATTEMPTS):
        lat = _tcp_probe(host, port)
        if lat is not None:
            best = lat if best is None else min(best, lat)
            break
        time.sleep(0.2)
    if best is None:
        return None
    node["latency"] = round(best, 1)
    return node


def test_all(nodes: list[dict]) -> list[dict]:
    """Test every node concurrently; return reachable nodes sorted by latency."""
    alive: list[dict] = []
    total = len(nodes)
    if total == 0:
        log("test: nothing to test")
        return alive

    done = 0
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
        futures = {pool.submit(test_node, n): n for n in nodes}
        for fut in as_completed(futures):
            done += 1
            try:
                res = fut.result()
            except Exception:  # noqa: BLE001 - defensive, test_node never raises
                res = None
            if res is not None:
                alive.append(res)
            if done % 500 == 0 or done == total:
                log(f"test: progress {done}/{total} ({len(alive)} alive)")

    alive.sort(key=lambda n: n.get("latency", 1e9))
    log(f"test: {len(alive)}/{total} nodes reachable "
        f"(workers={TCP_WORKERS}, timeout={TCP_TIMEOUT}s, attempts={TCP_ATTEMPTS})")
    return alive
