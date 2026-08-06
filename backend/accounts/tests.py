from rest_framework.test import APITestCase

from .models import User


class AuthFlowTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="alice", email="alice@example.com", password="Str0ngPass!", role=User.Role.USER
        )

    def test_login_success_sets_refresh_cookie_and_returns_access(self):
        response = self.client.post("/api/auth/login/", {"email": "alice@example.com", "password": "Str0ngPass!"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)
        self.assertIn("protectme_refresh", response.cookies)
        self.assertTrue(response.cookies["protectme_refresh"]["httponly"])

    def test_login_wrong_password_rejected(self):
        response = self.client.post("/api/auth/login/", {"email": "alice@example.com", "password": "wrong"})
        self.assertEqual(response.status_code, 401)

    def test_me_requires_valid_access_token(self):
        login = self.client.post("/api/auth/login/", {"email": "alice@example.com", "password": "Str0ngPass!"})
        access = login.data["access"]

        me = self.client.get("/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {access}")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.data["email"], "alice@example.com")

    def test_me_rejects_missing_token(self):
        response = self.client.get("/api/auth/me/")
        self.assertEqual(response.status_code, 401)

    def test_refresh_uses_cookie_to_issue_new_access_token(self):
        self.client.post("/api/auth/login/", {"email": "alice@example.com", "password": "Str0ngPass!"})
        # Le client de test conserve automatiquement les cookies recus, comme un navigateur
        refresh = self.client.post("/api/auth/refresh/")
        self.assertEqual(refresh.status_code, 200)
        self.assertIn("access", refresh.data)

    def test_refresh_fails_without_cookie(self):
        response = self.client.post("/api/auth/refresh/")
        self.assertEqual(response.status_code, 401)
