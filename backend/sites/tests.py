from rest_framework.test import APITestCase

from accounts.models import User

from .models import Site


class SiteAccessTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="bob", email="bob@example.com", password="Str0ngPass!", role=User.Role.USER)
        self.other_owner = User.objects.create_user(username="eve", email="eve@example.com", password="Str0ngPass!", role=User.Role.USER)
        self.admin = User.objects.create_user(username="root", email="admin@example.com", password="Str0ngPass!", role=User.Role.ADMIN)

    def _auth_header(self, email, password="Str0ngPass!"):
        login = self.client.post("/api/auth/login/", {"email": email, "password": password})
        return f"Bearer {login.data['access']}"

    def test_create_site_returns_raw_key_once(self):
        header = self._auth_header("bob@example.com")
        response = self.client.post("/api/sites/", {"name": "boutique-bob.com"}, HTTP_AUTHORIZATION=header)
        self.assertEqual(response.status_code, 201)
        self.assertIn("api_key", response.data)
        self.assertTrue(response.data["api_key"].startswith("sk_live_"))

    def test_user_only_sees_own_sites(self):
        Site.create_with_key(name="site-bob", owner=self.owner)
        Site.create_with_key(name="site-eve", owner=self.other_owner)

        header = self._auth_header("bob@example.com")
        response = self.client.get("/api/sites/", HTTP_AUTHORIZATION=header)
        names = [s["name"] for s in response.data]
        self.assertIn("site-bob", names)
        self.assertNotIn("site-eve", names)

    def test_admin_sees_all_sites(self):
        Site.create_with_key(name="site-bob", owner=self.owner)
        Site.create_with_key(name="site-eve", owner=self.other_owner)

        header = self._auth_header("admin@example.com")
        response = self.client.get("/api/sites/", HTTP_AUTHORIZATION=header)
        names = [s["name"] for s in response.data]
        self.assertIn("site-bob", names)
        self.assertIn("site-eve", names)
