import os
import tempfile
import unittest
from pathlib import Path


class ReportIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        os.environ["TRUTHLENS_DATABASE_URL"] = f"sqlite:///{Path(cls.temp_dir.name) / 'integrity.db'}"
        os.environ["TRUTHLENS_STORAGE_DIR"] = str(Path(cls.temp_dir.name) / "storage")
        os.environ["TRUTHLENS_AUTH_SECRET"] = "integrity-test-secret"
        os.environ["TRUTHLENS_PUBLIC_APP_URL"] = "https://truthlens.example.test/projects/truthlens-ai"

        from app.config import get_settings
        get_settings.cache_clear()
        from app.database import init_db
        init_db()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_saved_report_gets_hash_signature_and_verification_record(self):
        from app.services.analyzer import analyze_url_text
        from app.services.integrity import verification_record
        from app.services.storage import get_report, save_report

        report = analyze_url_text("https://secure-paypa1-login.xyz/verify/password")
        save_report(report, user_id=None)
        stored = get_report(report.id)

        self.assertIsNotNone(stored)
        self.assertEqual(len(stored.report_hash), 64)
        self.assertEqual(len(stored.report_signature), 64)
        self.assertTrue(stored.verification_url.endswith(f"/verify/{report.id}"))

        verification = verification_record(stored)
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["status"], "verified")
        self.assertEqual(verification["report_id"], report.id)


if __name__ == "__main__":
    unittest.main()
