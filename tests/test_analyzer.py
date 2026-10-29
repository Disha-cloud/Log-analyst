import json
import unittest
from unittest.mock import patch

from llm import analyzer

GOOD = {"summary": "s", "severity": "high", "attack_chain": [], "mitigations": []}


def reply(text):
    return {"message": {"content": text}}


class AnalyzerTests(unittest.TestCase):
    @patch("llm.analyzer.ollama_available", return_value=True)
    @patch("llm.analyzer.ollama.chat")
    def test_retry_after_invalid_json(self, chat, _):
        chat.side_effect = [reply("not json"), reply(json.dumps(GOOD))]
        result, attempts = analyzer.call_llm("prompt")
        self.assertEqual((attempts, result["severity"]), (2, "high"))

    @patch("llm.analyzer.ollama_available", return_value=True)
    @patch("llm.analyzer.ollama.chat")
    def test_two_invalid_replies_raise(self, chat, _):
        chat.side_effect = [reply("bad"), reply("still bad")]
        with self.assertRaises(ValueError):
            analyzer.call_llm("prompt")

    @patch("llm.analyzer.ollama_available", return_value=False)
    def test_ollama_down_raises_clear_error(self, _):
        with self.assertRaises(RuntimeError):
            analyzer.call_llm("prompt")

    def test_only_cited_evidence_sent(self):
        records = [{"evidence_id": "auth.log:L0001", "raw": "a"},
                   {"evidence_id": "auth.log:L0002", "raw": "b"}]
        findings = [{"evidence_ids": ["auth.log:L0002"]}]
        self.assertEqual(analyzer.select_evidence(records, findings), {"auth.log:L0002": "b"})

    def test_stage_is_enum(self):
        stage = analyzer.OUTPUT_SCHEMA["properties"]["attack_chain"]["items"]["properties"]["stage"]
        self.assertEqual(stage["enum"], analyzer.STAGES)


if __name__ == "__main__":
    unittest.main()