import unittest

from harness_mvp.knowledge import KnowledgeBase, KnowledgeEntry


class KnowledgeBaseTests(unittest.TestCase):
    def test_relevant_queries_match_cwe_sqli_xss_and_authorization(self):
        kb = KnowledgeBase()
        self.assertEqual(kb.search("CWE-89")[0].entry_id, "CWE-089")
        self.assertEqual(kb.search("SQLi database")[0].entry_id, "CWE-089")
        self.assertEqual(kb.search("reflected XSS browser")[0].entry_id, "CWE-079")
        self.assertEqual(kb.search("authorization admin route")[0].entry_id, "CWE-862")

    def test_unrelated_and_empty_queries_return_no_false_positive(self):
        kb = KnowledgeBase()
        self.assertEqual(kb.search("quantum banana telescope"), [])
        self.assertEqual(kb.search("   "), [])
        self.assertEqual(kb.search("sqli", limit=0), [])
        self.assertEqual(kb.search(None), [])  # type: ignore[arg-type]

    def test_empty_index_is_safe(self):
        self.assertEqual(KnowledgeBase([]).search("SQL injection"), [])

    def test_results_are_score_sorted_and_explain_retrieval(self):
        entries = [
            KnowledgeEntry("a", "SQL injection", "query input", ("sqli",), "CWE-89"),
            KnowledgeEntry("b", "Input validation", "query input validation", ("input",), "CWE-20"),
        ]
        result = KnowledgeBase(entries).search("SQL input", limit=2)
        self.assertEqual([entry.entry_id for entry in result], ["a", "b"])
        self.assertGreaterEqual(result[0].score, result[1].score)
        explanation = result[0].metadata["retrieval"]
        self.assertEqual(explanation["method"], "tf-idf-cosine")
        self.assertIn("score_meaning", explanation)
        self.assertIn("sql", explanation["matched_terms"])


if __name__ == "__main__":
    unittest.main()
