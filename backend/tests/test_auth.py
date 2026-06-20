import os
import tempfile
import unittest
from pathlib import Path


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        os.environ["TRUTHLENS_DATABASE_URL"] = f"sqlite:///{Path(cls.temp_dir.name) / 'auth.db'}"
        os.environ["TRUTHLENS_STORAGE_DIR"] = str(Path(cls.temp_dir.name) / "storage")
        os.environ["TRUTHLENS_AUTH_SECRET"] = "unit-test-auth-secret"
        os.environ["TRUTHLENS_ADMIN_EMAILS"] = "admin@example.test"

        from app.config import get_settings
        get_settings.cache_clear()
        from app.database import init_db
        init_db()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_register_login_and_session(self):
        from app.services.auth import authenticate_token, login_user, register_user

        user, token = register_user("Case Analyst", "analyst@example.test", "strong-pass-123")
        self.assertEqual(user["email"], "analyst@example.test")
        self.assertEqual(authenticate_token(token)["id"], user["id"])

        logged_in, login_token = login_user("analyst@example.test", "strong-pass-123")
        self.assertEqual(logged_in["id"], user["id"])
        self.assertEqual(authenticate_token(login_token)["email"], "analyst@example.test")

    def test_duplicate_registration_and_wrong_password_fail(self):
        from app.services.auth import login_user, register_user

        register_user("Second Analyst", "second@example.test", "strong-pass-456")
        with self.assertRaises(ValueError):
            register_user("Duplicate", "second@example.test", "strong-pass-456")
        with self.assertRaises(ValueError):
            login_user("second@example.test", "wrong-password")

    def test_configured_administrator_role(self):
        from app.services.auth import authenticate_token, register_user

        user, token = register_user("Administrator", "admin@example.test", "strong-admin-pass")
        self.assertEqual(user["role"], "administrator")
        self.assertEqual(authenticate_token(token)["role"], "administrator")


if __name__ == "__main__":
    unittest.main()
