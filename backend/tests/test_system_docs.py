import unittest

from app.services.system_docs import build_system_documentation, build_system_documentation_pdf


class SystemDocumentationTests(unittest.TestCase):
    def test_documentation_matches_active_implementation(self):
        documentation = build_system_documentation()
        integration_names = {item["name"]: item for item in documentation["integrations"]}

        self.assertEqual(documentation["frontend"]["framework"], "Next.js App Router")
        self.assertIn("users", {table["name"] for table in documentation["database"]["tables"]})
        self.assertEqual(integration_names["VirusTotal"]["status"], "Removed")
        self.assertNotIn("unit-test-auth-secret", str(documentation))
        self.assertIn("ANALYSIS FAILED", " ".join(documentation["pipelines"]["Audio"]))

    def test_documentation_pdf_is_generated(self):
        content = build_system_documentation_pdf(build_system_documentation())
        self.assertTrue(content.startswith(b"%PDF"))
        self.assertGreater(len(content), 1000)


if __name__ == "__main__":
    unittest.main()
