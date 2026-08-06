from django.conf import settings
from django.db import models

from sites.models import Site


class SupportTicket(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Ouvert"
        IN_PROGRESS = "in_progress", "En cours"
        CLOSED = "closed", "Ferme"

    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tickets")
    site = models.ForeignKey(Site, on_delete=models.SET_NULL, null=True, blank=True, related_name="tickets")
    subject = models.CharField(max_length=200)
    message = models.TextField()
    admin_reply = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"#{self.pk} {self.subject} ({self.status})"
