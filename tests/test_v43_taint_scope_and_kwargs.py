import unittest

from openguard.config import AuditConfig
from openguard.scanners.code_security_scanner import CodeSecurityScanner
from openguard.scanners.taint_analyzer import PythonTaintAnalyzer


class TestTaintScopeAndKwargs(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = CodeSecurityScanner(AuditConfig())

    def test_js_startsWith_url_prefix_and_prior_route_guard_do_not_hide_path_traversal(self) -> None:
        js_code = (
            "const fs = require('fs');\n"
            "app.get('/safe', (req, res) => {\n"
            "  const resolved = path.resolve('/srv', req.query.f);\n"
            "  if (!resolved.startsWith(baseDir)) return res.status(403).end();\n"
            "  res.send(fs.readFileSync(resolved, 'utf8'));\n"
            "});\n"
            "app.get('/vuln', (req, res) => {\n"
            "  if (req.query.cb.startsWith('https://')) console.log('ok');\n"
            "  const data = fs.readFileSync(req.query.path, 'utf8');\n"
            "  res.send(data);\n"
            "});\n"
        )
        hits = self.scanner.scan_content(js_code, "routes.js")
        path_hits = [h for h in hits if h.rule_id == "OG-TAINT-JS-004"]
        self.assertEqual(len(path_hits), 1)
        self.assertEqual(path_hits[0].line_number, 9)

    def test_python_taint_detects_keyword_args_for_subprocess_and_open(self) -> None:
        py_code = (
            "import subprocess\n"
            "from flask import request\n"
            "def handler():\n"
            "    cmd = request.args.get('cmd')\n"
            "    subprocess.run(args=cmd, shell=True)\n"
            "    fpath = request.args.get('file')\n"
            "    with open(file=fpath) as fh:\n"
            "        return fh.read()\n"
        )
        hits = PythonTaintAnalyzer().analyze(py_code, "app.py")
        ids = {h.rule_id for h in hits}
        self.assertIn("OG-TAINT-PY-002", ids)
        self.assertIn("OG-TAINT-PY-004", ids)


if __name__ == "__main__":
    unittest.main()
