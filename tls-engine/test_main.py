import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from main import run_pipeline


class MainPipelineTests(unittest.TestCase):
    def test_pipeline_keeps_all_evidence_in_one_file(self):
        evidence = {
            "network": {
                "stream_id": 1,
                "protocol": "IMAP",
                "port": 993,
                "server_hostname": "imap.gmail.com",
                "encryption": "tls",
            }
        }

        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            tls = {"reachable": True, "tls_mode": "implicit", "tls_version": "TLSv1.3"}
            analysis = {"security_score": 100, "risk_level": "LOW", "findings": []}
            with patch("main.scan_tls", return_value=tls), \
                    patch("main.analyze", return_value=analysis), \
                    patch.dict("sys.modules", {
                        "spf_checker": type("SpfModule", (), {"check_spf": staticmethod(lambda domain: {"spf": {"record_found": True, "finding": "STRONG_SPF_POLICY"}})})(),
                        "dkim_checker": type("DkimModule", (), {"check_dkim": staticmethod(lambda domain: {"dkim": {"record_found": False, "finding": "DKIM_SELECTOR_NOT_FOUND"}})})(),
                        "dmarc_checker": type("DmarcModule", (), {"check_dmarc": staticmethod(lambda domain: {"dmarc": {"record_found": True, "policy": "reject", "finding": "STRONG_DMARC_POLICY"}})})(),
                    }):
                result = run_pipeline(str(evidence_path))

            stored = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertEqual(set(stored), {"network", "tls", "spf", "dkim", "dmarc"})
            self.assertEqual(result["security_score"], 100)


if __name__ == "__main__":
    unittest.main()
