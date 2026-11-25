"""
Phase 8 Unit Tests: Master Orchestrator, Legacy-Fast Mode, and API Server Handler.
"""

import unittest
import io
import json
from unittest.mock import MagicMock

from core.orchestrator.orchestrator import OptimizationOrchestrator, CompilationResult
from api.server import EnclaveHTTPHandler
import api.server as server_module


class MockHTTPHandler(EnclaveHTTPHandler):
    """Subclass of EnclaveHTTPHandler to test endpoints without live socket binding."""

    def __init__(self, method: str, path: str, body: bytes = b""):
        self.command = method
        self.path = path
        self.headers = {"Content-Length": str(len(body)), "Content-Type": "application/json"}
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.requestline = f"{method} {path} HTTP/1.1"
        self.request_version = "HTTP/1.1"
        self.close_connection = False
        self.status_code = None
        self.response_headers = {}

    def send_response(self, code, message=None):
        self.status_code = code

    def send_header(self, keyword, value):
        self.response_headers[keyword] = value

    def end_headers(self):
        pass


class TestPhase8OrchestratorAndApi(unittest.TestCase):

    def setUp(self):
        server_module.global_safe_stopped = False
        self.orchestrator = OptimizationOrchestrator()

    def test_orchestrator_zero_trust_compilation_lifecycle(self):
        source = (
            "extern \"C\" int calculate(int x) {\n"
            "    int a = x * 2;\n"
            "    int b = a + 10;\n"
            "    return b;\n"
            "}\n"
        )
        res = self.orchestrator.compile(source_code=source, filename="calc.cpp", mode="zero-trust")

        self.assertTrue(res.success)
        self.assertEqual(res.verdict, "accept")
        self.assertIn("INIT", res.states_traversed)
        self.assertIn("QUARANTINE_OK", res.states_traversed)
        self.assertIn("FRONTEND", res.states_traversed)
        self.assertIn("RELEASE", res.states_traversed)
        self.assertTrue(len(res.baseline_ir) > 0)
        self.assertTrue(len(res.optimized_ir) > 0)
        self.assertIsNotNone(res.signature)
        self.assertTrue(len(res.signature) > 16)
        self.assertTrue(len(res.audit_chain_head) == 64)

    def test_orchestrator_legacy_fast_mode(self):
        source = (
            "extern \"C\" void vector_add(const float* a, const float* b, float* c, int n) {\n"
            "    for (int i = 0; i < n; ++i) c[i] = a[i] + b[i];\n"
            "}\n"
        )
        res = self.orchestrator.compile(source_code=source, filename="vec.cpp", mode="legacy-fast")

        self.assertTrue(res.success)
        self.assertEqual(res.mode, "legacy-fast")
        self.assertEqual(res.verdict, "accept")
        self.assertIn("sroa", res.passes_applied)
        self.assertIsNotNone(res.signature)

    def test_api_status_endpoint(self):
        handler = MockHTTPHandler("GET", "/api/status")
        handler.do_GET()

        self.assertEqual(handler.status_code, 200)
        body = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertEqual(body["status"], "ONLINE")
        self.assertEqual(body["states_count"], 22)

    def test_api_web_dashboard_served(self):
        handler = MockHTTPHandler("GET", "/")
        handler.do_GET()

        self.assertEqual(handler.status_code, 200)
        html = handler.wfile.getvalue().decode("utf-8")
        self.assertIn("Agentic AI Compiler Enclave", html)
        self.assertIn("Deterministic 22-State Machine", html)

    def test_api_compile_endpoint(self):
        payload = json.dumps({
            "source_code": "int square(int x) { return x * x; }",
            "filename": "square.cpp",
            "mode": "zero-trust"
        }).encode("utf-8")

        handler = MockHTTPHandler("POST", "/api/compile", body=payload)
        handler.do_POST()

        self.assertEqual(handler.status_code, 200)
        body = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertTrue(body["success"])
        self.assertIn("baseline_ir", body)
        self.assertIn("optimized_ir", body)
        self.assertIsNotNone(body["signature"])

    def test_api_safe_stop_kill_switch(self):
        # 1. Trigger safe stop
        stop_handler = MockHTTPHandler("POST", "/api/safe_stop", body=b"{}")
        stop_handler.do_POST()

        self.assertEqual(stop_handler.status_code, 200)
        stop_body = json.loads(stop_handler.wfile.getvalue().decode("utf-8"))
        self.assertEqual(stop_body["status"], "HALTED")
        self.assertTrue(server_module.global_safe_stopped)

        # 2. Compile after halt must return 403 Forbidden
        compile_handler = MockHTTPHandler("POST", "/api/compile", body=b'{"source_code": "int a;"}')
        compile_handler.do_POST()

        self.assertEqual(compile_handler.status_code, 403)
        fail_body = json.loads(compile_handler.wfile.getvalue().decode("utf-8"))
        self.assertFalse(fail_body["success"])
        self.assertIn("EMERGENCY_HALT", fail_body["error"])


if __name__ == "__main__":
    unittest.main()
