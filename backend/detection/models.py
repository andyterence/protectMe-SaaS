from django.db import models

from sites.models import Site


class ConnectionLog(models.Model):
    """Trace CHAQUE connexion passant par le middleware sur un site client -
    contrairement a AttackLog qui est volontairement selectif. Sert a
    repondre a "qui se connecte sur mon site", pas au reentrainement du
    modele (d'ou la separation stricte des deux tables : melanger du trafic
    normal massif dans AttackLog degraderait la qualite du futur jeu de
    donnees de reentrainement).

    Volume assume : purge via `python manage.py cleanup_old_logs`, a
    planifier en cron cote serveur (aucune dependance supplementaire).
    """

    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name="connection_logs")
    ip = models.GenericIPAddressField()
    browser_type = models.CharField(max_length=50, blank=True)
    protocol_type = models.CharField(max_length=10, blank=True)
    probability = models.FloatField()
    is_attack = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["site", "created_at"]),
            models.Index(fields=["ip"]),
        ]
        ordering = ["-created_at"]


class AttackLog(models.Model):
    """Stockage SELECTIF (cf. cahier des charges) : seules les requetes
    depassant SUSPICION_THRESHOLD sont journalisees ici, jamais chaque
    requete. Le statut par defaut est 'pending_review' - c'est l'Admin ou
    le User (site owner) qui requalifie ensuite via le dashboard, et c'est
    ce jeu de donnees requalifie qui sert au reentrainement du modele.
    """

    class Status(models.TextChoices):
        PENDING = "pending_review", "En attente de revue"
        CONFIRMED = "confirmed", "Attaque confirmee"
        FALSE_POSITIVE = "false_positive", "Faux positif"

    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name="attack_logs")
    ip = models.GenericIPAddressField()
    features = models.JSONField()
    probability = models.FloatField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["site", "created_at"]),
            models.Index(fields=["ip"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.site.name} · {self.ip} · {self.probability:.2f} · {self.status}"
