from rest_framework.test import APITestCase

from accounts.models import User
from sites.models import Site

from .models import AttackLog, ConnectionLog

NORMAL_FEATURES = {
    "network_packet_size": 400, "protocol_type": "TCP", "login_attempts": 2,
    "session_duration": 100, "encryption_used": "AES", "ip_reputation_score": 0.1,
    "failed_logins": 0, "browser_type": "Chrome", "unusual_time_access": 0,
    "_client_ip": "203.0.113.10",
}

ATTACK_FEATURES = {
    "network_packet_size": 400, "protocol_type": "TCP", "login_attempts": 10,
    "session_duration": 50, "encryption_used": "None", "ip_reputation_score": 0.9,
    "failed_logins": 5, "browser_type": "Unknown", "unusual_time_access": 1,
    "_client_ip": "203.0.113.99",
}


class DetectEndpointTests(APITestCase):
    def setUp(self):
        owner = User.objects.create_user(username="carl", email="carl@example.com", password="Str0ngPass!")
        self.site, self.raw_key = Site.create_with_key(name="site-carl", owner=owner)

    def test_normal_traffic_not_blocked_but_always_connection_logged(self):
        response = self.client.post(
            "/api/v1/detect", NORMAL_FEATURES, format="json", HTTP_X_API_KEY=self.raw_key
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["attack_detected"])
        self.assertEqual(AttackLog.objects.count(), 0)     # stockage selectif : rien sous le seuil de suspicion
        self.assertEqual(ConnectionLog.objects.count(), 1)  # mais la connexion elle-meme est toujours tracee
        self.assertFalse(ConnectionLog.objects.first().is_attack)

    def test_attack_traffic_blocked_and_logged_in_both_tables(self):
        response = self.client.post(
            "/api/v1/detect", ATTACK_FEATURES, format="json", HTTP_X_API_KEY=self.raw_key
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["attack_detected"])
        self.assertEqual(AttackLog.objects.count(), 1)
        self.assertEqual(ConnectionLog.objects.count(), 1)
        self.assertTrue(ConnectionLog.objects.first().is_attack)
        log = AttackLog.objects.first()
        self.assertEqual(log.site, self.site)
        self.assertEqual(log.status, AttackLog.Status.PENDING)

    def test_missing_api_key_rejected(self):
        response = self.client.post("/api/v1/detect", NORMAL_FEATURES, format="json")
        self.assertEqual(response.status_code, 401)

    def test_invalid_api_key_rejected(self):
        response = self.client.post(
            "/api/v1/detect", NORMAL_FEATURES, format="json", HTTP_X_API_KEY="sk_live_bogus"
        )
        self.assertEqual(response.status_code, 401)

    def test_response_contains_request_id_for_traceability(self):
        response = self.client.post(
            "/api/v1/detect", NORMAL_FEATURES, format="json", HTTP_X_API_KEY=self.raw_key
        )
        self.assertIn("request_id", response.data)


class DashboardLogEndpointsTests(APITestCase):
    """Les ecrans "qui a attaque" et "qui se connecte" du dashboard."""

    def setUp(self):
        self.owner = User.objects.create_user(username="hugo", email="hugo@example.com", password="Str0ngPass!", role=User.Role.USER)
        self.stranger = User.objects.create_user(username="ivy", email="ivy@example.com", password="Str0ngPass!", role=User.Role.USER)
        self.site, self.raw_key = Site.create_with_key(name="site-hugo", owner=self.owner)

    def _auth(self, email):
        login = self.client.post("/api/auth/login/", {"email": email, "password": "Str0ngPass!"})
        return f"Bearer {login.data['access']}"

    def test_attack_log_list_scoped_to_owner(self):
        self.client.post("/api/v1/detect", ATTACK_FEATURES, format="json", HTTP_X_API_KEY=self.raw_key)

        owner_view = self.client.get("/api/v1/attack-logs/", HTTP_AUTHORIZATION=self._auth("hugo@example.com"))
        self.assertEqual(len(owner_view.data), 1)

        stranger_view = self.client.get("/api/v1/attack-logs/", HTTP_AUTHORIZATION=self._auth("ivy@example.com"))
        self.assertEqual(len(stranger_view.data), 0)

    def test_review_endpoint_requalifies_a_log(self):
        self.client.post("/api/v1/detect", ATTACK_FEATURES, format="json", HTTP_X_API_KEY=self.raw_key)
        log = AttackLog.objects.first()

        response = self.client.patch(
            f"/api/v1/attack-logs/{log.id}/review/", {"status": "confirmed"},
            HTTP_AUTHORIZATION=self._auth("hugo@example.com"), format="json",
        )
        self.assertEqual(response.status_code, 200)
        log.refresh_from_db()
        self.assertEqual(log.status, AttackLog.Status.CONFIRMED)

    def test_connection_log_list_includes_normal_traffic(self):
        self.client.post("/api/v1/detect", NORMAL_FEATURES, format="json", HTTP_X_API_KEY=self.raw_key)

        response = self.client.get("/api/v1/connection-logs/", HTTP_AUTHORIZATION=self._auth("hugo@example.com"))
        self.assertEqual(len(response.data), 1)
        self.assertFalse(response.data[0]["is_attack"])


class SimulateEndpointTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="jack", email="jack@example.com", password="Str0ngPass!", role=User.Role.USER)

    def _auth(self):
        login = self.client.post("/api/auth/login/", {"email": "jack@example.com", "password": "Str0ngPass!"})
        return f"Bearer {login.data['access']}"

    def test_preset_simulation_does_not_persist_anything(self):
        response = self.client.post(
            "/api/v1/simulate/", {"preset": "brute_force"},
            HTTP_AUTHORIZATION=self._auth(), format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["attack_detected"])
        self.assertEqual(AttackLog.objects.count(), 0)
        self.assertEqual(ConnectionLog.objects.count(), 0)

    def test_unknown_preset_without_custom_features_is_rejected(self):
        response = self.client.post(
            "/api/v1/simulate/", {"preset": "does_not_exist"},
            HTTP_AUTHORIZATION=self._auth(), format="json",
        )
        self.assertEqual(response.status_code, 400)


class CleanupCommandTests(APITestCase):
    def setUp(self):
        owner = User.objects.create_user(username="karim", email="karim@example.com", password="Str0ngPass!")
        self.site, _ = Site.create_with_key(name="site-karim", owner=owner)

    def test_cleanup_deletes_only_old_connection_logs(self):
        from datetime import timedelta

        from django.core.management import call_command
        from django.utils import timezone

        old_log = ConnectionLog.objects.create(site=self.site, ip="203.0.113.1", probability=0.1)
        ConnectionLog.objects.filter(pk=old_log.pk).update(created_at=timezone.now() - timedelta(days=40))

        recent_log = ConnectionLog.objects.create(site=self.site, ip="203.0.113.2", probability=0.1)

        call_command("cleanup_old_logs", "--days=30")

        remaining_ips = set(ConnectionLog.objects.values_list("ip", flat=True))
        self.assertNotIn("203.0.113.1", remaining_ips)
        self.assertIn("203.0.113.2", remaining_ips)


class IpReputationEnrichmentTests(APITestCase):
    def setUp(self):
        owner = User.objects.create_user(username="dana", email="dana@example.com", password="Str0ngPass!")
        self.site, self.raw_key = Site.create_with_key(name="site-dana", owner=owner)

    def test_ip_with_confirmed_attack_history_gets_higher_reputation_score(self):
        from detection.ml import enrich_ip_reputation

        AttackLog.objects.create(
            site=self.site, ip="198.51.100.5", features={}, probability=0.9,
            status=AttackLog.Status.CONFIRMED,
        )
        AttackLog.objects.create(
            site=self.site, ip="198.51.100.5", features={}, probability=0.35,
            status=AttackLog.Status.FALSE_POSITIVE,
        )

        score = enrich_ip_reputation("198.51.100.5")
        self.assertEqual(score, 0.5)  # 1 confirmee sur 2 logs pour cette IP

        unseen_ip_score = enrich_ip_reputation("192.0.2.1")
        self.assertEqual(unseen_ip_score, 0.0)
