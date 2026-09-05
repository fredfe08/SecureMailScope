import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzer import analyze
from dkim_checker import check_dkim
from dmarc_checker import check_dmarc
from domain_utils import get_organizational_domain
from spf_checker import check_spf


class CombinedEvidenceAnalyzerTests(unittest.TestCase):
    def analyze_evidence(self, evidence):
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            output_path = Path(directory) / "analysis.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            return analyze(str(evidence_path), str(output_path))

    def base(self, **sections):
        evidence = {
            "network": {
                "stream_id": 1,
                "protocol": "IMAP",
                "port": 993,
                "server_hostname": "imap.gmail.com",
                "encryption": "tls",
            },
            "tls": {
                "reachable": True,
                "tls_mode": "implicit",
                "tls_version": "TLSv1.3",
                "cipher_name": "TLS_AES_256_GCM_SHA384",
                "certificate_status": "Valid",
                "days_until_expiration": 57,
                "hostname_matches_san": True,
            },
        }
        evidence.update(sections)
        return evidence

    def finding_types(self, result):
        return {finding["finding_type"] for finding in result["findings"]}

    def test_organizational_domain_is_separate_from_server_hostname(self):
        self.assertEqual(get_organizational_domain("imap.gmail.com"), "gmail.com")

    def test_plaintext_and_valid_modern_tls(self):
        evidence = self.base()
        evidence["network"]["encryption"] = "plaintext"
        result = self.analyze_evidence(evidence)
        self.assertEqual(result["security_score"], 70)
        self.assertIn("PLAINTEXT_COMMUNICATION", self.finding_types(result))

    def test_tls_findings(self):
        cases = [
            ({"tls_version": "TLSv1.0"}, "DEPRECATED_TLS_VERSION", 80),
            ({"cipher_name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}, "WEAK_CIPHER", 80),
            ({"certificate_status": "Invalid"}, "INVALID_CERTIFICATE", 80),
            ({"days_until_expiration": -1}, "EXPIRED_CERTIFICATE", 80),
            ({"days_until_expiration": 10}, "CERTIFICATE_EXPIRING_SOON", 90),
            ({"hostname_matches_san": False}, "CERTIFICATE_HOSTNAME_MISMATCH", 80),
        ]
        for tls_update, finding, score in cases:
            with self.subTest(finding=finding):
                evidence = self.base()
                evidence["tls"].update(tls_update)
                result = self.analyze_evidence(evidence)
                self.assertIn(finding, self.finding_types(result))
                self.assertEqual(result["security_score"], score)

    def test_certificate_expiration_is_not_double_counted(self):
        evidence = self.base()
        evidence["tls"].update({"certificate_status": "Expired", "days_until_expiration": -3})
        result = self.analyze_evidence(evidence)
        findings = [item for item in result["findings"] if item["finding_type"] == "EXPIRED_CERTIFICATE"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(result["security_score"], 80)

    def test_tls_failure_does_not_create_property_findings(self):
        evidence = self.base()
        evidence["tls"] = {"reachable": False, "error": "connection refused"}
        result = self.analyze_evidence(evidence)
        self.assertEqual(self.finding_types(result), {"TLS_CONNECTION_FAILED"})
        self.assertEqual(result["security_score"], 100)

    def test_starttls_downgrade_is_potential_only(self):
        evidence = self.base()
        evidence["network"]["encryption"] = "plaintext"
        evidence["tls"].update({"tls_mode": "starttls", "starttls_supported": True})
        result = self.analyze_evidence(evidence)
        self.assertIn("POTENTIAL_STARTTLS_DOWNGRADE", self.finding_types(result))
        self.assertEqual(result["security_score"], 45)

    def test_email_auth_scoring(self):
        cases = [
            ({"record_found": True, "finding": "STRONG_SPF_POLICY"}, 100),
            ({"record_found": True, "finding": "SOFTFAIL_SPF_POLICY"}, 90),
            ({"record_found": False, "finding": "SPF_RECORD_MISSING"}, 80),
        ]
        for spf, score in cases:
            with self.subTest(spf=spf["finding"]):
                self.assertEqual(self.analyze_evidence(self.base(spf=spf))["security_score"], score)

        self.assertEqual(
            self.analyze_evidence(self.base(dkim={"record_found": False, "finding": "DKIM_SELECTOR_NOT_FOUND"}))["security_score"],
            100,
        )
        self.assertEqual(
            self.analyze_evidence(self.base(dkim={"record_found": None, "finding": "DKIM_DNS_LOOKUP_FAILED", "error": "timeout"}))["security_score"],
            100,
        )

        dmarc_cases = [("reject", 100), ("quarantine", 95), ("none", 90)]
        for policy, score in dmarc_cases:
            with self.subTest(policy=policy):
                evidence = self.base(dmarc={"record_found": True, "policy": policy})
                self.assertEqual(self.analyze_evidence(evidence)["security_score"], score)
        self.assertEqual(
            self.analyze_evidence(self.base(dmarc={"record_found": False, "finding": "DMARC_RECORD_MISSING"}))["security_score"],
            80,
        )
        self.assertEqual(
            self.analyze_evidence(self.base(dmarc={"record_found": None, "finding": "DNS_LOOKUP_FAILED", "error": "timeout"}))["security_score"],
            100,
        )

    def test_expected_current_evidence_score_is_fifty(self):
        evidence = self.base(
            spf={"record_found": True, "record": "v=spf1 redirect=_spf.google.com", "policy": "Not specified", "finding": "SPF_POLICY_NOT_SPECIFIED", "domain": "gmail.com"},
            dkim={"record_found": False, "finding": "DKIM_SELECTOR_NOT_FOUND", "domain": "gmail.com"},
            dmarc={"record_found": True, "policy": "none", "finding": "MONITOR_ONLY_DMARC_POLICY", "domain": "gmail.com"},
        )
        evidence["network"]["encryption"] = "plaintext"
        result = self.analyze_evidence(evidence)
        self.assertEqual(result["security_score"], 50)
        self.assertEqual(result["risk_level"], "HIGH")


class DNSCheckerTests(unittest.TestCase):
    def test_dns_failures_remain_explicit(self):
        with patch("dns.resolver.Resolver.resolve", side_effect=TimeoutError("timed out")):
            self.assertEqual(check_spf("gmail.com")["spf"]["finding"], "DNS_LOOKUP_FAILED")
            self.assertEqual(check_dmarc("gmail.com")["dmarc"]["finding"], "DNS_LOOKUP_FAILED")
            self.assertEqual(check_dkim("gmail.com")["dkim"]["finding"], "DKIM_DNS_LOOKUP_FAILED")

    def test_checkers_use_google_dns(self):
        with patch("spf_checker.dns.resolver.Resolver") as resolver_class:
            resolver_class.return_value.resolve.side_effect = TimeoutError("timed out")
            check_spf("gmail.com")
            self.assertEqual(resolver_class.return_value.nameservers, ["8.8.8.8"])


if __name__ == "__main__":
    unittest.main()
