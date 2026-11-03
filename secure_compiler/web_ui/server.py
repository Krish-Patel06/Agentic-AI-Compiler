"""
Secure Compiler — Zero-Dependency Web UI Server
Provides an interactive real-time dashboard visualizing build metadata,
candidate trees, correctness gates, security gates, and statistical benchmarks.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import http.server
import socketserver
import threading
import webbrowser
import json
import time
import os
from pathlib import Path


STATIC_DIR = Path(__file__).parent / "static"


class SecureCompilerHandler(http.server.SimpleHTTPRequestHandler):
    summary_path: str = ""
    audit_path: str = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        if path in ("/api/status", "/api/results"):
            self._serve_json(self._get_status_data())
        elif path == "/api/audit":
            self._serve_json(self._get_audit_data())
        else:
            self._inject_no_cache = True
            super().do_GET()

    def end_headers(self):
        if getattr(self, "_inject_no_cache", False):
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self._inject_no_cache = False
        super().end_headers()

    def _serve_json(self, data: dict):
        try:
            raw = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(raw)
        except Exception as e:
            self.send_error(500, str(e))

    def _get_status_data(self) -> dict:
        if self.summary_path and os.path.exists(self.summary_path):
            try:
                with open(self.summary_path, "r", encoding="utf-8", errors="replace") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"status": "waiting", "message": "No build summary loaded."}

    def _get_audit_data(self) -> dict:
        if self.audit_path and os.path.exists(self.audit_path):
            try:
                with open(self.audit_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                    if "timeline" not in data and "events" in data:
                        data["timeline"] = data["events"]
                    return data
            except Exception:
                pass
        return {"timeline": []}

    def log_message(self, format, *args):
        pass


class SecureWebUIServer:
    def __init__(self, summary_path: str, audit_path: str, port: int = 8080):
        self.summary_path = summary_path
        self.audit_path = audit_path
        self.port = port
        self._server = None
        self._thread = None

        SecureCompilerHandler.summary_path = summary_path
        SecureCompilerHandler.audit_path = audit_path

    def start(self) -> bool:
        try:
            self._server = http.server.ThreadingHTTPServer(("0.0.0.0", self.port), SecureCompilerHandler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            print(f"[WebUI] Server listening at http://localhost:{self.port} and http://127.0.0.1:{self.port}")
            return True
        except Exception as e:
            print(f"[WebUI] Server failed to start on port {self.port}: {e}")
            return False

    def open_browser(self, delay: float = 0.5):
        def _open():
            time.sleep(delay)
            webbrowser.open(f"http://localhost:{self.port}")
        threading.Thread(target=_open, daemon=True).start()

    def stop(self):
        if self._server:
            self._server.shutdown()
