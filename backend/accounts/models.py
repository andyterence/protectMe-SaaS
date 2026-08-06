from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Utilisateur du dashboard : soit un 'User' (proprietaire de site),
    soit l' 'Admin' (Developpeur du Modele), conformement au cahier des
    charges. On authentifie par email plutot que par username - plus
    naturel pour un SaaS.
    """

    class Role(models.TextChoices):
        ADMIN = "admin", "Admin (Developpeur du Modele)"
        USER = "user", "User (Proprietaire de site)"

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.USER)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self):
        return f"{self.email} ({self.role})"
