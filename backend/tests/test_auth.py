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

    def test_otp_login_and_admin_role(self):
        from app.services.auth import authenticate_token, request_login_otp, verify_login_otp, register_user

        admin, _ = register_user("Founder", "akshaykalakonda9@gmail.com", "admin-pass-123")
        self.assertEqual(admin["role"], "founder_admin")

        challenge = request_login_otp("akshaykalakonda9@gmail.com", "admin-pass-123")
        self.assertEqual(challenge["status"], "otp_required")
        logged_in, token = verify_login_otp(challenge["challenge_id"], challenge["dev_otp"])
        self.assertEqual(logged_in["role"], "founder_admin")
        self.assertEqual(authenticate_token(token)["email"], "akshaykalakonda9@gmail.com")

    def test_login_otp_requires_existing_registration(self):
        from app.services.auth import request_login_otp

        with self.assertRaisesRegex(ValueError, "register first"):
            request_login_otp("missing@example.test", "password-123")


if __name__ == "__main__":
    unittest.main()
