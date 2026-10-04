"""HTTP API tests: run the real server on an ephemeral port."""
import base64
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.server import make_server  # noqa: E402
from builder import (ClassBuilder, legal_construction_class,  # noqa: E402
                     uninitialized_escape_class)


def b64(data):
    return base64.b64encode(data).decode("ascii")


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path):
        try:
            with urllib.request.urlopen(self.url(path), timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def post(self, obj, raw=None):
        data = raw if raw is not None else json.dumps(obj).encode("utf-8")
        req = urllib.request.Request(
            self.url("/api/verify"), data=data,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_health(self):
        status, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "ok"})

    def test_index_page(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"<textarea", body)
        self.assertIn(b"/api/verify", body)

    def test_unknown_path_404(self):
        status, _ = self.get("/nope")
        self.assertEqual(status, 404)

    def test_verify_pass(self):
        status, res = self.post({"class_b64": b64(legal_construction_class())})
        self.assertEqual(status, 200)
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["method"], "run")
        self.assertGreater(len(res["states"]), 0)
        self.assertEqual(res["handlers"][0]["stack"],
                         ["ref java/lang/Throwable"])

    def test_verify_reject_locates_offset(self):
        status, res = self.post({"class_b64": b64(uninitialized_escape_class())})
        self.assertEqual(status, 200)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "uninitialized-escapes-to-handler")
        self.assertEqual(res["error"]["offset"], 4)

    def test_base64_with_embedded_whitespace_accepted(self):
        raw = b64(legal_construction_class())
        wrapped = "\n".join(raw[i:i + 40] for i in range(0, len(raw), 40))
        status, res = self.post({"class_b64": wrapped})
        self.assertEqual(status, 200)
        self.assertTrue(res["ok"], res.get("error"))

    def test_invalid_base64(self):
        status, res = self.post({"class_b64": "###not-base64###"})
        self.assertEqual(status, 400)
        self.assertEqual(res["error"]["kind"], "invalid-base64")

    def test_oversize_class_rejected(self):
        status, res = self.post({"class_b64": b64(b"\x00" * 70000)})
        self.assertEqual(status, 400)
        self.assertEqual(res["error"]["kind"], "class-too-large")

    def test_non_json_body(self):
        status, res = self.post(None, raw=b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(res["error"]["kind"], "bad-request")

    def test_missing_field(self):
        status, res = self.post({"nope": 1})
        self.assertEqual(status, 400)
        self.assertEqual(res["error"]["kind"], "bad-request")

    def test_unknown_method(self):
        status, res = self.post({"class_b64": b64(legal_construction_class()),
                                 "method": "zz"})
        self.assertEqual(status, 200)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "no-target-method")

    def test_ambiguous_then_named(self):
        b = ClassBuilder()
        b.add_method("ma", bytes([0xB1]), max_stack=0, max_locals=0)
        b.add_method("mb", bytes([0xB1]), max_stack=0, max_locals=0)
        data = b64(b.build())
        status, res = self.post({"class_b64": data})
        self.assertEqual(status, 200)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "ambiguous-method")
        status, res = self.post({"class_b64": data, "method": "mb"})
        self.assertEqual(status, 200)
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["method"], "mb")


if __name__ == "__main__":
    unittest.main()
