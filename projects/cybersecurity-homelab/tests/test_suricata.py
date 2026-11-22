import json
import unittest
from pathlib import Path

from csf.soc import IDSParser, LogAnalyzer


class SuricataTests(unittest.TestCase):
    def test_fixture_uses_alert_severity_in_the_report(self):
        fixture = Path(__file__).resolve().parents[1] / 'examples' / 'suricata.eve.jsonl'
        result = LogAnalyzer().analyze_logs(fixture)

        self.assertEqual(result['total_events'], 2)
        self.assertEqual(result['incidents_detected'], 1)
        self.assertEqual(result['incidents'][0]['severity'], 8.0)

    def test_invalid_and_unrelated_records_do_not_interrupt_ingestion(self):
        lines = [
            'not JSON',
            '[]',
            '{"event_type":"flow","src_ip":"192.0.2.10"}',
            '{"src_ip":"192.0.2.10","alert":[]}',
            '{"src_ip":"192.0.2.10","alert":{"signature_id":"7"}}',
            json.dumps({'src_ip': '192.0.2.10', 'alert': {'signature_id': 7, 'severity': 3}}),
        ]
        events = IDSParser().parse_suricata('\n'.join(lines))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].alert_name, 'Suricata alert')
        self.assertEqual(events[0].severity, 4.0)

    def test_unknown_severity_falls_back_to_low(self):
        record = {'src_ip': '192.0.2.10', 'alert': {'signature_id': 7, 'severity': []}}
        events = IDSParser().parse_suricata(json.dumps(record))

        self.assertEqual(events[0].alert_id, 7)
        self.assertEqual(events[0].severity, 0.1)

    def test_unicode_separator_inside_json_string_is_preserved(self):
        name = 'Synthetic first line\u2028second line'
        record = {'src_ip': '192.0.2.10', 'alert': {'signature': name, 'severity': 2}}
        line = json.dumps(record, ensure_ascii=False)

        events = IDSParser().parse_suricata(line + '\r\n')

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].alert_name, name)
