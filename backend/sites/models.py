import hashlib
import secrets

from django.conf import settings
from django.db import models


def _hash_key(raw_key: str) -> str:
    """SHA-256 suffit ici : contrairement a un mot de passe (faible entropie,
    devine-able), une cle API generee par secrets.token_urlsafe a une entropie
    tres elevee. Un hash lent type bcrypt ajouterait une latence inutile sur
    CHAQUE requete /v1/detect, ce qui va a l'encontre du besoin temps reel.
    """
    return hashlib.sha256(raw_key.encode()).hexdigest()


class Site(models.Model):
    """Un site client integre au service, au sens SaaS multi-tenant.
    C'est la cle etrangere presente sur chaque AttackLog pour isoler les
    donnees entre clients.
    """

    name = models.CharField(max_length=255)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sites")
    api_key_hash = models.CharField(max_length=64, unique=True, db_index=True)
    api_key_prefix = models.CharField(max_length=12)  # affichage seul, ex: "sk_live_ab12"
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} ({self.api_key_prefix}…)"

    @classmethod
    def create_with_key(cls, name: str, owner) -> tuple["Site", str]:
        """Genere une nouvelle cle API. La valeur RAW n'est jamais stockee ni
        recuperable ensuite - exactement comme Stripe/AWS : on l'affiche une
        seule fois a la creation, au developpeur du site client de la copier.
        """
        raw_key = f"sk_live_{secrets.token_urlsafe(32)}"
        site = cls.objects.create(
            name=name,
            owner=owner,
            api_key_hash=_hash_key(raw_key),
            api_key_prefix=raw_key[:12],
        )
        return site, raw_key

    @staticmethod
    def resolve_from_raw_key(raw_key: str) -> "Site | None":
        try:
            return Site.objects.select_related("owner").get(
                api_key_hash=_hash_key(raw_key), is_active=True
            )
        except Site.DoesNotExist:
            return None

    def regenerate_key(self) -> str:
        """Invalide l'ancienne clé, en génère une nouvelle. La clé brute
        n'est retournée qu'ici, jamais stockée ni recupérable ensuite."""
        raw_key = f"sk_live_{secrets.token_urlsafe(32)}"
        self.api_key_hash = _hash_key(raw_key)
        self.api_key_prefix = raw_key[:12]
        self.save(update_fields=["api_key_hash", "api_key_prefix"])
        return raw_key