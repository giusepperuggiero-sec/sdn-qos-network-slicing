"""Thread-safe Prometheus HTTP metrics exporter for OpenFlow port statistics."""

from __future__ import annotations

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import threading
from typing import Any


def escape_prometheus_label(value: Any) -> str:
    """Escape backslash, double-quote, and newline characters in Prometheus labels."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def format_prometheus_metrics(metrics_snapshot: dict[Any, dict[Any, dict[str, int | float]]]) -> str:
    """Render an OpenFlow port-stats snapshot in Prometheus text exposition v0.0.4."""
    lines = [
        "# HELP ofp_port_rx_bytes_total Total number of received bytes",
        "# TYPE ofp_port_rx_bytes_total counter",
        "# HELP ofp_port_tx_bytes_total Total number of transmitted bytes",
        "# TYPE ofp_port_tx_bytes_total counter",
        "# HELP ofp_port_rx_packets_total Total number of received packets",
        "# TYPE ofp_port_rx_packets_total counter",
        "# HELP ofp_port_tx_packets_total Total number of transmitted packets",
        "# TYPE ofp_port_tx_packets_total counter",
        "# HELP ofp_port_rx_errors_total Total number of received errors",
        "# TYPE ofp_port_rx_errors_total counter",
        "# HELP ofp_port_tx_errors_total Total number of transmitted errors",
        "# TYPE ofp_port_tx_errors_total counter",
    ]

    for dpid in sorted(metrics_snapshot, key=lambda item: str(item)):
        port_stats = metrics_snapshot[dpid]
        for port_no in sorted(port_stats, key=lambda item: str(item)):
            stats = port_stats[port_no]
            if not isinstance(stats, dict):
                continue
            labels = (
                f'dpid="{escape_prometheus_label(dpid)}",'
                f'port="{escape_prometheus_label(port_no)}"'
            )
            lines.append(f'ofp_port_rx_bytes_total{{{labels}}} {stats.get("rx_bytes", 0)}')
            lines.append(f'ofp_port_tx_bytes_total{{{labels}}} {stats.get("tx_bytes", 0)}')
            lines.append(f'ofp_port_rx_packets_total{{{labels}}} {stats.get("rx_packets", 0)}')
            lines.append(f'ofp_port_tx_packets_total{{{labels}}} {stats.get("tx_packets", 0)}')
            lines.append(f'ofp_port_rx_errors_total{{{labels}}} {stats.get("rx_errors", 0)}')
            lines.append(f'ofp_port_tx_errors_total{{{labels}}} {stats.get("tx_errors", 0)}')

    return "\n".join(lines) + "\n"


class _ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


class MetricsStore:
    """Thread-safe container protecting OpenFlow port counters shared across threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[Any, dict[Any, dict[str, int | float]]] = {}

    def update_dpid(self, dpid: Any, port_stats: dict[Any, dict[str, int | float]]) -> None:
        with self._lock:
            self._data[dpid] = deepcopy(port_stats)

    def remove_dpid(self, dpid: Any) -> None:
        with self._lock:
            self._data.pop(dpid, None)

    def snapshot(self) -> dict[Any, dict[Any, dict[str, int | float]]]:
        with self._lock:
            return deepcopy(self._data)


class MetricsServer(threading.Thread):
    """Daemon HTTP server exporting thread-safe OpenFlow counters on `/metrics`."""

    def __init__(
        self,
        port: int | None = None,
        host: str | None = None,
        store: MetricsStore | None = None,
    ) -> None:
        super().__init__(daemon=True)
        self.host = host if host is not None else os.getenv("PROMETHEUS_HOST", "127.0.0.1")
        self.port = port if port is not None else int(os.getenv("PROMETHEUS_PORT", "8000"))
        self.store = store if store is not None else MetricsStore()
        self.httpd: HTTPServer | None = None
        self.ready = threading.Event()

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        store = self.store

        class MetricsHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path != "/metrics":
                    self.send_error(404, "Not Found")
                    return
                payload = format_prometheus_metrics(store.snapshot()).encode("utf-8")
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    return

            def log_message(self, format: str, *args: Any) -> None:
                return

        return MetricsHandler

    def run(self) -> None:
        try:
            self.httpd = _ReusableHTTPServer((self.host, self.port), self._build_handler())
            # Update effective port when port=0 is used in tests before signaling ready
            self.port = int(self.httpd.server_address[1])
            self.ready.set()
            print(f"[PROMETHEUS] Metrics server listening on {self.host}:{self.port}/metrics")
            self.httpd.serve_forever()
        except OSError as exc:
            self.ready.set()
            print(f"[PROMETHEUS ERROR] Unable to start metrics server: {exc}")

    def stop(self) -> None:
        if self.httpd is not None:
            print("[PROMETHEUS] Stopping metrics server")
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
