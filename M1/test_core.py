import unittest
from securemailscope_m1.analyze import capture_quality, tls_evidence
from securemailscope_m1.certificates import parse_der
from securemailscope_m1.extract import find_starttls, normalize_packets
from securemailscope_m1.handoff import build_handoff


def packet(frame, layers, protocols="eth:ip:tcp"):
    return {"_source": {"layers": {"frame": {"frame.number": str(frame), "frame.protocols": protocols, "frame.time_epoch": "1.0", "frame.len": "100"}, **layers}}}

class CoreTests(unittest.TestCase):
    def test_starttls_order_and_no_false_success(self):
        raw = [
            packet(1, {"tcp": {"tcp.stream": "0", "tcp.srcport": "40000", "tcp.dstport": "25", "tcp.flags": "0x002", "tcp.len": "0"}}, "eth:ip:tcp:smtp"),
            packet(2, {"tcp": {"tcp.stream": "0"}, "smtp": {"smtp.req": "STARTTLS"}}, "eth:ip:tcp:smtp"),
        ]
        events = find_starttls(normalize_packets(raw))
        self.assertEqual(events[0]["status"], "ATTEMPTED")
        self.assertFalse(events[0]["tls_followed"])

    def test_starttls_requires_clienthello_after_positive_response(self):
        raw = [
            packet(1, {"tcp": {"tcp.stream": "0"}, "smtp": {"smtp.req": "STARTTLS"}}, "eth:ip:tcp:smtp"),
            packet(2, {"tcp": {"tcp.stream": "0"}, "smtp": {"smtp.response": "220 Ready to start TLS"}}, "eth:ip:tcp:smtp"),
            packet(3, {"tcp": {"tcp.stream": "0"}, "tls": {"tls.handshake.type": "2"}}, "eth:ip:tcp:tls"),
        ]
        event = find_starttls(normalize_packets(raw))[0]
        self.assertEqual(event["status"], "ACKNOWLEDGED")
        self.assertFalse(event["tls_followed"])

        raw.append(packet(4, {"tcp": {"tcp.stream": "0"}, "tls": {"tls.handshake.type": "1"}}, "eth:ip:tcp:tls"))
        event = find_starttls(normalize_packets(raw))[0]
        self.assertEqual(event["status"], "TLS_FOLLOWED")

    def test_starttls_advertisement_is_not_attempt(self):
        raw = [packet(1, {"tcp": {"tcp.stream": "0"}, "smtp": {"smtp.response": "250-STARTTLS"}}, "eth:ip:tcp:smtp")]
        event = find_starttls(normalize_packets(raw))[0]
        self.assertEqual(event["status"], "ADVERTISED")
        self.assertFalse(event["attempted"])

    def test_starttls_advertisement_can_use_tcp_payload(self):
        raw = [packet(1, {"tcp": {"tcp.stream": "0", "tcp.payload": "32:35:30:2d:53:54:41:52:54:54:4c:53:0d:0a"}, "smtp": {"smtp.response": "250-capability"}}, "eth:ip:tcp:smtp")]
        event = find_starttls(normalize_packets(raw))[0]
        self.assertEqual(event["status"], "ADVERTISED")

    def test_no_tls_is_insufficient_evidence(self):
        records = normalize_packets([packet(1, {"tcp": {"tcp.stream": "0", "tcp.flags": "0x002"}})])
        self.assertEqual(tls_evidence(records)["status"], "INSUFFICIENT_EVIDENCE")
        self.assertIsNone(tls_evidence(records)["handshake_complete"])

    def test_serverhello_is_not_complete(self):
        raw = [packet(1, {"tls": {"tls.handshake.type": "2", "tls.handshake.extensions.supported_version": "0x0304"}}, "eth:ip:tcp:tls")]
        evidence = tls_evidence(normalize_packets(raw))
        self.assertFalse(evidence["handshake_complete"])
        self.assertIn("TLS 1.3", evidence["tls_versions"])

    def test_repeated_tls_handshake_fields_are_preserved(self):
        raw = [packet(1, {"tls": {"tls.handshake.type": ["1", "2"], "tls.handshake.extensions.supported_version": ["0x0304", "0x0303"]}}, "eth:ip:tcp:tls")]
        evidence = tls_evidence(normalize_packets(raw))
        self.assertEqual([stage["stage"] for stage in evidence["handshake_stages"]], ["ClientHello", "ServerHello"])
        self.assertEqual(evidence["supported_versions"], ["TLS 1.2", "TLS 1.3"])

    def test_invalid_certificate_is_preserved_as_failure(self):
        result = parse_der(b"not-a-certificate")
        self.assertTrue(result["parse_status"].startswith("failed:"))
        self.assertEqual(result["self_signed"], None)

    def test_capture_quality_is_heuristic(self):
        raw = [packet(1, {"tcp": {"tcp.stream": "0", "tcp.flags": "0x002"}})]
        records = normalize_packets(raw)
        quality = capture_quality(records, raw)
        self.assertEqual(quality["tcp_syn_packets"], 1)
        self.assertTrue(any("Heuristic" in x for x in quality["notes"]))

    def test_handoff_preserves_client_server_direction(self):
        records = normalize_packets([
            packet(1, {"ip": {"ip.src": "192.168.1.10", "ip.dst": "142.250.195.27"}, "tcp": {"tcp.stream": "0", "tcp.srcport": "50000", "tcp.dstport": "993"}}, "eth:ip:tcp:imap"),
        ])
        handoff = build_handoff(records, [])
        self.assertEqual(handoff["network"]["client_ip"], "192.168.1.10")
        self.assertEqual(handoff["network"]["server_ip"], "142.250.195.27")

    def test_handshake_complete_requires_single_stream(self):
        raw = [
            packet(1, {"tcp": {"tcp.stream": "0"}, "tls": {"tls.handshake.type": "1"}}, "eth:ip:tcp:tls"),
            packet(2, {"tcp": {"tcp.stream": "1"}, "tls": {"tls.handshake.type": "2"}}, "eth:ip:tcp:tls"),
            packet(3, {"tcp": {"tcp.stream": "1"}, "tls": {"tls.handshake.type": "20"}}, "eth:ip:tcp:tls"),
        ]
        evidence = tls_evidence(normalize_packets(raw))
        self.assertFalse(evidence["handshake_complete"])

        raw.append(packet(4, {"tcp": {"tcp.stream": "1"}, "tls": {"tls.handshake.type": "1"}}, "eth:ip:tcp:tls"))
        evidence = tls_evidence(normalize_packets(raw))
        self.assertTrue(evidence["handshake_complete"])

    def test_handoff_stream_id_matches_reported_endpoints(self):
        records = normalize_packets([
            packet(1, {"ip": {"ip.src": "10.0.0.99", "ip.dst": "10.0.0.100"}, "tcp": {"tcp.stream": "0", "tcp.srcport": "51000", "tcp.dstport": "8080"}}, "eth:ip:tcp"),
            packet(2, {"ip": {"ip.src": "192.168.1.10", "ip.dst": "142.250.195.27"}, "tcp": {"tcp.stream": "1", "tcp.srcport": "50000", "tcp.dstport": "25"}}, "eth:ip:tcp:smtp"),
        ])
        handoff = build_handoff(records, [])
        self.assertEqual(handoff["network"]["stream_id"], 1)
        self.assertEqual(handoff["network"]["client_ip"], "192.168.1.10")
        self.assertEqual(handoff["network"]["server_ip"], "142.250.195.27")

    def test_handshake_completion_requires_known_stream(self):
        raw = [
            packet(1, {"tls": {"tls.handshake.type": "1"}}, "eth:ip:tcp:tls"),
            packet(2, {"tls": {"tls.handshake.type": "2"}}, "eth:ip:tcp:tls"),
            packet(3, {"tls": {"tls.handshake.type": "20"}}, "eth:ip:tcp:tls"),
        ]
        self.assertFalse(tls_evidence(normalize_packets(raw))["handshake_complete"])

    def test_handoff_exposes_m2_placeholders(self):
        handoff = build_handoff([], [])
        self.assertIn("m2", handoff)
        self.assertIsNone(handoff["m2"]["spf"])
        self.assertIsNone(handoff["m2"]["dkim"])
        self.assertIsNone(handoff["m2"]["dmarc"])
        self.assertIsNone(handoff["m2"]["risk"])

if __name__ == "__main__": unittest.main()
