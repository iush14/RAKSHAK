"""
Comprehensive unit and integration tests for Phase 2 Email/Password Auth & Verification.
Covers all 24 required test cases:
1. Register creates unverified user.
2. Password is hashed.
3. Plain password is not stored.
4. Verification token is hashed before storage.
5. Raw token is not stored.
6. Registration calls email service.
7. Invalid email rejected.
8. Weak/invalid password rejected according to chosen rules.
9. Valid verification succeeds.
10. Invalid verification token fails.
11. Expired verification token fails.
12. Used token cannot be reused.
13. Unverified account cannot login.
14. Verified account can login.
15. Wrong password cannot login.
16. Successful login creates existing user session.
17. /api/auth/me returns authenticated email user.
18. Resend creates a new token.
19. Resend is throttled.
20. Verification attempts are throttled.
21. Existing GitHub OAuth authentication still works.
22. Existing GitHub users are not broken.
23. Notification endpoints still work for authenticated email users.
24. Backend 401 does not become "Backend Offline".
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app, upsert_github_user
from app.models import User, EmailVerificationToken, Notification
from app.auth_service import hash_password, verify_password, hash_token, validate_password_strength
from conftest import authenticate_client, create_workspace_user


@pytest.fixture
def client():
    return TestClient(app)


class TestEmailAuthComprehensive:

    def test_01_06_register_creates_unverified_user_hashes_and_calls_email(self, client):
        """Tests 1, 2, 3, 4, 5, 6: Registration behavior, secure storage, and email dispatch."""
        test_email = "alice.secops@example.com"
        plain_pw = "SecurePass123!@"

        with patch("app.main.send_verification_email", return_value={"success": True, "id": "msg_mock_123"}) as mock_email:
            res = client.post("/api/auth/register", json={"email": test_email, "password": plain_pw})
            assert res.status_code in (200, 201), res.text
            data = res.json()
            assert data["success"] is True
            assert "email" in data
            assert mock_email.called
            # Verify called with keyword args to_email and raw_token
            call_kwargs = mock_email.call_args.kwargs
            assert call_kwargs["to_email"] == test_email.lower()
            raw_token = call_kwargs["raw_token"]
            assert len(raw_token) >= 32

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == test_email.lower()).first()
            assert user is not None
            # 1. Unverified initially
            assert user.is_verified is False
            # 2. Password is hashed (Argon2 prefix)
            assert user.hashed_password.startswith("$argon2id$")
            # 3. Plain password is NOT stored
            assert plain_pw not in user.hashed_password
            assert verify_password(plain_pw, user.hashed_password) is True

            # 4 & 5. Verification token is hashed, raw token is not stored in DB
            token_record = db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).first()
            assert token_record is not None
            assert token_record.token_hash == hash_token(raw_token)
            assert raw_token != token_record.token_hash
        finally:
            db.close()

    def test_07_invalid_email_rejected(self, client):
        """Test 7: Invalid email formats rejected."""
        bad_emails = ["notanemail", "@example.com", "alice@", "alice space@example.com", ""]
        for bad in bad_emails:
            res = client.post("/api/auth/register", json={"email": bad, "password": "ValidPassword123!"})
            assert res.status_code in (400, 422), f"Expected failure for {bad}"

    def test_08_weak_password_rejected(self, client):
        """Test 8: Weak passwords that don't meet complexity criteria are rejected."""
        weak_passwords = [
            "short1!",          # < 8 chars
            "nouppercase123!",  # no uppercase
            "NOLOWERCASE123!",  # no lowercase
            "NoDigitsHere!!",   # no digit
            "NoSpecialChars123",# no special char
        ]
        for weak in weak_passwords:
            res = client.post("/api/auth/register", json={"email": "good.email@example.com", "password": weak})
            assert res.status_code in (400, 422)
            assert "password" in res.text.lower()

    def test_09_12_valid_verification_succeeds_and_cannot_reuse_or_use_invalid(self, client):
        """Tests 9, 10, 11, 12: Token validation, expiry, and single-use enforcement."""
        test_email = "verify.flow@example.com"
        plain_pw = "VerificationP@ss1"

        raw_token = None
        with patch("app.main.send_verification_email", return_value={"success": True, "id": "mock_id"}) as mock_email:
            client.post("/api/auth/register", json={"email": test_email, "password": plain_pw})
            raw_token = mock_email.call_args.kwargs["raw_token"]

        # 10. Invalid token fails
        bad_res = client.post("/api/auth/verify-email", json={"token": "completely-invalid-raw-token-12345"})
        assert bad_res.status_code == 400
        assert "Invalid" in bad_res.text

        # 9. Valid verification succeeds
        good_res = client.post("/api/auth/verify-email", json={"token": raw_token})
        assert good_res.status_code == 200
        assert good_res.json()["success"] is True

        # Check DB state
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == test_email.lower()).first()
            assert user.is_verified is True
            token_record = db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).first()
            assert token_record.used_at is not None
        finally:
            db.close()

        # 12. Used token cannot be reused
        reuse_res = client.post("/api/auth/verify-email", json={"token": raw_token})
        assert reuse_res.status_code == 400
        assert "already been used" in reuse_res.text or "Invalid" in reuse_res.text

    def test_11_expired_token_fails(self, client):
        """Test 11: Expired verification tokens fail safely."""
        test_email = "expired.test@example.com"
        plain_pw = "ExpiredP@ssword1!"

        raw_token = None
        with patch("app.main.send_verification_email", return_value={"success": True, "id": "mock_id"}) as mock_email:
            client.post("/api/auth/register", json={"email": test_email, "password": plain_pw})
            raw_token = mock_email.call_args.kwargs["raw_token"]

        # Manually expire the token in DB
        db = SessionLocal()
        try:
            token_record = db.query(EmailVerificationToken).filter(
                EmailVerificationToken.token_hash == hash_token(raw_token)
            ).first()
            token_record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
            db.commit()
        finally:
            db.close()

        res = client.post("/api/auth/verify-email", json={"token": raw_token})
        assert res.status_code in (400, 422)
        assert "expired" in res.text.lower()

    def test_13_16_login_unverified_vs_verified_and_wrong_password(self, client):
        """Tests 13, 14, 15, 16: Login flow for unverified, verified, and bad password."""
        test_email = "login.test@example.com"
        plain_pw = "LoginTestP@ss1!"

        raw_token = None
        with patch("app.main.send_verification_email", return_value={"success": True, "id": "mock_id"}) as mock_email:
            client.post("/api/auth/register", json={"email": test_email, "password": plain_pw})
            raw_token = mock_email.call_args.kwargs["raw_token"]

        # 13. Unverified account cannot login
        unverified_res = client.post("/api/auth/login", json={"email": test_email, "password": plain_pw})
        assert unverified_res.status_code == 403
        assert "verification required" in unverified_res.text.lower()

        # 15. Wrong password cannot login
        wrong_pw_res = client.post("/api/auth/login", json={"email": test_email, "password": "WrongPassword123!"})
        assert wrong_pw_res.status_code == 401

        # Verify email now
        client.post("/api/auth/verify-email", json={"token": raw_token})

        # 14 & 16. Verified account can login and session is established
        good_login_res = client.post("/api/auth/login", json={"email": test_email, "password": plain_pw})
        assert good_login_res.status_code == 200
        assert good_login_res.json().get("authenticated") is True or good_login_res.json().get("success") is True

        # Check /api/auth/me returns authenticated email user
        me_res = client.get("/api/auth/me")
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["authenticated"] is True
        assert me_data["user"]["email"] == test_email.lower()
        assert me_data["user"]["is_verified"] is True

    def test_18_19_resend_verification_and_throttling(self, client):
        """Tests 18 & 19: Resending creates fresh token and throttles rapid requests."""
        test_email = "resend.test@example.com"
        plain_pw = "ResendP@ssword1!"

        with patch("app.main.send_verification_email", return_value={"success": True, "id": "mock_id"}):
            client.post("/api/auth/register", json={"email": test_email, "password": plain_pw})

        # Set existing token created_at back in time to bypass registration cooldown
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == test_email.lower()).first()
            token_rec = db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).first()
            token_rec.created_at = datetime.now(timezone.utc) - timedelta(seconds=70)
            db.commit()
        finally:
            db.close()

        # First resend should succeed
        with patch("app.main.send_verification_email", return_value={"success": True, "id": "mock_id"}) as mock_email:
            res1 = client.post("/api/auth/resend-verification", json={"email": test_email})
            assert res1.status_code == 200
            assert mock_email.called

        # Rapid second resend without delay should be throttled (429)
        with patch("app.main.send_verification_email", return_value={"success": True, "id": "mock_id"}):
            res2 = client.post("/api/auth/resend-verification", json={"email": test_email})
            assert res2.status_code == 429
            assert "wait" in res2.text.lower()

    def test_20_verification_attempts_throttled(self, client):
        """Test 20: Max attempts on invalid token causes rate limiting / invalidation."""
        test_email = "throttle.token@example.com"
        plain_pw = "ThrottleP@ss1!"

        raw_token = None
        with patch("app.main.send_verification_email", return_value={"success": True, "id": "mock_id"}) as mock_email:
            client.post("/api/auth/register", json={"email": test_email, "password": plain_pw})
            raw_token = mock_email.call_args.kwargs["raw_token"]

        # Simulate exceeded failed verification attempts
        db = SessionLocal()
        try:
            token_rec = db.query(EmailVerificationToken).filter(
                EmailVerificationToken.token_hash == hash_token(raw_token)
            ).first()
            token_rec.attempts = 6  # Exceeded max allowed attempts (5)
            db.commit()
        finally:
            db.close()

        res = client.post("/api/auth/verify-email", json={"token": raw_token})
        assert res.status_code in (400, 422)
        assert "exceeded" in res.text.lower() or "invalid" in res.text.lower()

    def test_21_22_github_oauth_compatibility_and_linking(self, client):
        """Tests 21 & 22: GitHub OAuth accounts remain verified and link safely."""
        db = SessionLocal()
        try:
            # 1. Existing GitHub user is treated as verified
            gh_user = upsert_github_user(
                db=db,
                github_user={
                    "id": 777001,
                    "login": "octocat-dev",
                    "name": "The Octocat",
                    "avatar_url": "https://github.com/images/error/octocat_happy.gif",
                    "html_url": "https://github.com/octocat",
                    "email": "octocat@github.com",
                }
            )
            assert gh_user.is_verified is True
            assert gh_user.github_login == "octocat-dev"
            assert gh_user.email == "octocat@github.com"
            assert gh_user.hashed_password is None

            # 2. Email user signs up, then logs in with GitHub using same email
            email_user = User(
                email="linked.user@example.com",
                hashed_password=hash_password("LinkedP@ssword1!"),
                is_verified=True,
                created_at=datetime.now(timezone.utc)
            )
            db.add(email_user)
            db.commit()
            db.refresh(email_user)
            original_pw_hash = email_user.hashed_password

            # GitHub OAuth callback with same email links GitHub ID without destroying password
            linked_user = upsert_github_user(
                db=db,
                github_user={
                    "id": 888002,
                    "login": "linked-user-gh",
                    "name": "Linked User",
                    "avatar_url": "https://avatars.github.com/u/888002",
                    "html_url": "https://github.com/linked-user-gh",
                    "email": "linked.user@example.com",
                }
            )
            assert linked_user.id == email_user.id
            assert linked_user.github_user_id == 888002
            assert linked_user.hashed_password == original_pw_hash
            assert linked_user.is_verified is True
        finally:
            db.close()

    def test_23_notification_endpoints_work_for_authenticated_email_users(self, client):
        """Test 23: Workspace-scoped notifications work seamlessly for email-authenticated users."""
        db = SessionLocal()
        try:
            email_user = User(
                email="notif.user@example.com",
                hashed_password=hash_password("NotifP@ssword1!"),
                is_verified=True,
                created_at=datetime.now(timezone.utc)
            )
            db.add(email_user)
            db.commit()
            db.refresh(email_user)

            # Create notification for this user
            notif = Notification(
                user_id=email_user.id,
                notification_type="security_alert",
                title="Email User Alert",
                message="Your workspace scan completed.",
                severity="high",
                is_read=False,
                created_at=datetime.now(timezone.utc)
            )
            db.add(notif)
            db.commit()
        finally:
            db.close()

        # Login with email user
        login_res = client.post("/api/auth/login", json={"email": "notif.user@example.com", "password": "NotifP@ssword1!"})
        assert login_res.status_code == 200

        # Fetch notifications
        notif_res = client.get("/api/notifications")
        assert notif_res.status_code == 200
        data = notif_res.json()
        assert data["unread_count"] >= 1
        assert any(n["title"] == "Email User Alert" for n in data["notifications"])

    def test_24_backend_401_does_not_become_backend_offline(self, client):
        """Test 24: Unauthenticated GET /api/notifications returns HTTP 401 without crashing backend."""
        # Unauthenticated request
        res = client.get("/api/notifications")
        assert res.status_code == 401
        # Health check proves backend is reachable and online
        health_res = client.get("/health")
        assert health_res.status_code == 200
        assert health_res.json().get("status") == "healthy"

    def test_25_email_login_has_github_disconnected_by_default(self, client):
        """Test 25: Email-authenticated account has github_connected=False by default."""
        test_email = "pure.email@example.com"
        plain_pw = "PureEmailP@ss1!"

        with patch("app.main.send_verification_email", return_value={"success": True, "id": "mock_id"}) as mock_email:
            client.post("/api/auth/register", json={"email": test_email, "password": plain_pw})
            raw_token = mock_email.call_args.kwargs["raw_token"]

        # Verify email
        client.post("/api/auth/verify-email", json={"token": raw_token})

        # Check /api/auth/me reports github_connected=False
        me_res = client.get("/api/auth/me")
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["authenticated"] is True
        assert me_data["github_connected"] is False
        assert me_data["github_user"] is None
        assert me_data["user"]["email"] == test_email.lower()

        # Calling /api/github/repos returns 401 (GitHub not connected)
        repos_res = client.get("/api/github/repos")
        assert repos_res.status_code == 401
        assert "not connected" in repos_res.text.lower() or "authentication required" in repos_res.text.lower()

    def test_26_linking_github_to_active_email_user(self, client):
        """Test 26: Linking GitHub to an existing email user sets github_connected=True without duplicate accounts."""
        db = SessionLocal()
        try:
            email_user = User(
                email="link.target@example.com",
                hashed_password=hash_password("LinkTargetP@ss1!"),
                is_verified=True,
                created_at=datetime.now(timezone.utc)
            )
            db.add(email_user)
            db.commit()
            db.refresh(email_user)
            target_user_id = email_user.id
            orig_pw_hash = email_user.hashed_password
        finally:
            db.close()

        # Login email user
        login_res = client.post("/api/auth/login", json={"email": "link.target@example.com", "password": "LinkTargetP@ss1!"})
        assert login_res.status_code == 200

        # Link GitHub identity with current_user_id
        db = SessionLocal()
        try:
            linked_user = upsert_github_user(
                db=db,
                github_user={
                    "id": 999888,
                    "login": "octo-linked",
                    "name": "Octo Linked",
                    "avatar_url": "https://avatars.github.com/u/999888",
                    "html_url": "https://github.com/octo-linked",
                },
                current_user_id=target_user_id
            )
            assert linked_user.id == target_user_id
            assert linked_user.github_user_id == 999888
            assert linked_user.github_login == "octo-linked"
            assert linked_user.hashed_password == orig_pw_hash
            assert linked_user.email == "link.target@example.com"
        finally:
            db.close()

    def test_27_derive_display_name_and_me_identity(self, client):
        test_email = 'hackerofcoc.14@gmail.com'
        with patch('app.main.send_verification_email', return_value={'success': True, 'id': 'mock_1'}):
            r = client.post(
                '/api/auth/register',
                json={'email': test_email, 'password': 'StrongPassword!123'},
            )
            assert r.status_code in (200, 201)
            assert r.json()['success'] is True

        # Directly verify in DB to test login & me
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == test_email).first()
            user.is_verified = True
            db.commit()
        finally:
            db.close()

        # Login
        r_login = client.post(
            '/api/auth/login',
            json={'email': test_email, 'password': 'StrongPassword!123'},
        )
        assert r_login.status_code == 200
        assert r_login.json()['user']['display_name'] == 'Hackerofcoc'
        assert r_login.json()['github_connected'] is False

        # /api/auth/me
        r_me = client.get('/api/auth/me')
        assert r_me.status_code == 200
        assert r_me.json()['authenticated'] is True
        assert r_me.json()['user']['display_name'] == 'Hackerofcoc'
        assert r_me.json()['github_connected'] is False
        assert r_me.json()['github_user'] is None

    def test_28_github_account_already_linked_conflict(self, client):
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            u1 = User(
                email='user1_owner@example.com',
                hashed_password='xxx',
                is_verified=True,
                github_user_id='777888',
                github_login='github_hero',
                created_at=now,
                last_seen_at=now,
            )
            u2 = User(
                email='user2_attacker@example.com',
                hashed_password='xxx',
                is_verified=True,
                created_at=now,
                last_seen_at=now,
            )
            db.add_all([u1, u2])
            db.commit()
            db.refresh(u1)
            db.refresh(u2)

            # Attempt to link GitHub 777888 to User 2
            with pytest.raises(Exception) as exc_info:
                upsert_github_user(
                    db=db,
                    github_user={'id': 777888, 'login': 'github_hero', 'email': 'user1_owner@example.com'},
                    current_user_id=u2.id,
                )
            assert 'already linked to another' in str(exc_info.value)
        finally:
            db.close()

    def test_29_disconnect_github_endpoint(self, client):
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            u = User(
                email='user_disconnect@example.com',
                hashed_password='xxx',
                is_verified=True,
                github_user_id='999111',
                github_login='dc_user',
                created_at=now,
                last_seen_at=now,
            )
            db.add(u)
            db.commit()
            db.refresh(u)
            user_id = u.id
        finally:
            db.close()

        # Unauthenticated call returns 401
        r_dc_unauth = client.post('/api/auth/github/disconnect')
        assert r_dc_unauth.status_code == 401

        # Authenticate client
        authenticate_client(client, user=u)
        r_dc = client.post('/api/auth/github/disconnect')
        assert r_dc.status_code == 200
        assert r_dc.json()['success'] is True

    def test_30_oauth_state_generation_and_validation(self, client):
        # /api/auth/github generates random state and select_account
        r = client.get('/api/auth/github', follow_redirects=False)
        assert r.status_code in (302, 307)
        loc = r.headers.get('location', '')
        assert 'state=' in loc
        assert 'prompt=select_account' in loc

        # /api/auth/github/callback with invalid state redirects with error
        r_cb = client.get('/api/auth/github/callback?code=fake_code&state=invalid_state', follow_redirects=False)
        assert r_cb.status_code in (302, 307)
        assert 'oauth_state_invalid' in r_cb.headers.get('location', '')

    def test_31_logout_clears_all_session_data(self, client):
        test_email = 'logout_test@example.com'
        with patch('app.main.send_verification_email', return_value={'success': True, 'id': 'mock_1'}):
            client.post(
                '/api/auth/register',
                json={'email': test_email, 'password': 'Password123!'},
            )
        db = SessionLocal()
        try:
            u = db.query(User).filter(User.email == test_email).first()
            u.is_verified = True
            db.commit()
        finally:
            db.close()

        client.post(
            '/api/auth/login',
            json={'email': test_email, 'password': 'Password123!'},
        )
        # Verify authenticated
        r_me = client.get('/api/auth/me')
        assert r_me.json()['authenticated'] is True

        # Logout
        r_logout = client.post('/api/auth/logout')
        assert r_logout.status_code == 200

        # /api/auth/me should now report unauthenticated
        r_me2 = client.get('/api/auth/me')
        assert r_me2.json()['authenticated'] is False
        assert r_me2.json()['user'] is None

    def test_32_register_with_custom_name_preserves_identity(self, client):
        test_email = 'ayush.shewale@example.com'
        test_name = 'Ayush Shewale'
        test_pw = 'StrongPassword!123'

        with patch('app.main.send_verification_email', return_value={'success': True, 'id': 'mock_id_32'}):
            r_reg = client.post(
                '/api/auth/register',
                json={'email': test_email, 'password': test_pw, 'name': test_name},
            )
            assert r_reg.status_code in (200, 201)

        # Confirm stored in DB
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == test_email).first()
            assert user is not None
            assert user.name == test_name
            # Mark verified
            user.is_verified = True
            db.commit()
        finally:
            db.close()

        # Login
        r_login = client.post(
            '/api/auth/login',
            json={'email': test_email, 'password': test_pw},
        )
        assert r_login.status_code == 200
        assert r_login.json()['user']['name'] == test_name
        assert r_login.json()['user']['display_name'] == test_name

        # /api/auth/me
        r_me = client.get('/api/auth/me')
        assert r_me.status_code == 200
        assert r_me.json()['authenticated'] is True
        assert r_me.json()['user']['name'] == test_name
        assert r_me.json()['user']['display_name'] == test_name

