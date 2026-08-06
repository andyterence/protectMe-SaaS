from rest_framework.test import APITestCase

from accounts.models import User

from .models import SupportTicket


class SupportTicketTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="finn", email="finn@example.com", password="Str0ngPass!", role=User.Role.USER)
        self.other_user = User.objects.create_user(username="gina", email="gina@example.com", password="Str0ngPass!", role=User.Role.USER)
        self.admin = User.objects.create_user(username="root", email="admin@example.com", password="Str0ngPass!", role=User.Role.ADMIN)

    def _auth(self, email):
        login = self.client.post("/api/auth/login/", {"email": email, "password": "Str0ngPass!"})
        return f"Bearer {login.data['access']}"

    def test_user_can_create_and_see_own_ticket(self):
        header = self._auth("finn@example.com")
        create = self.client.post(
            "/api/tickets/", {"subject": "Faux positifs frequents", "message": "Mon site legitime est souvent bloque."},
            HTTP_AUTHORIZATION=header,
        )
        self.assertEqual(create.status_code, 201)
        self.assertEqual(create.data["status"], SupportTicket.Status.OPEN)

        listing = self.client.get("/api/tickets/", HTTP_AUTHORIZATION=header)
        self.assertEqual(len(listing.data), 1)

    def test_user_cannot_see_others_tickets(self):
        SupportTicket.objects.create(created_by=self.other_user, subject="Autre probleme", message="...")
        header = self._auth("finn@example.com")
        listing = self.client.get("/api/tickets/", HTTP_AUTHORIZATION=header)
        self.assertEqual(len(listing.data), 0)

    def test_admin_sees_all_tickets(self):
        SupportTicket.objects.create(created_by=self.user, subject="A", message="...")
        SupportTicket.objects.create(created_by=self.other_user, subject="B", message="...")
        header = self._auth("admin@example.com")
        listing = self.client.get("/api/tickets/", HTTP_AUTHORIZATION=header)
        self.assertEqual(len(listing.data), 2)

    def test_only_admin_can_reply_and_close_ticket(self):
        ticket = SupportTicket.objects.create(created_by=self.user, subject="A", message="...")

        user_header = self._auth("finn@example.com")
        denied = self.client.patch(f"/api/tickets/{ticket.id}/", {"status": "closed"}, HTTP_AUTHORIZATION=user_header, format="json")
        self.assertEqual(denied.status_code, 403)

        admin_header = self._auth("admin@example.com")
        allowed = self.client.patch(
            f"/api/tickets/{ticket.id}/",
            {"status": "closed", "admin_reply": "Regle, merci."},
            HTTP_AUTHORIZATION=admin_header, format="json",
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.data["status"], "closed")
