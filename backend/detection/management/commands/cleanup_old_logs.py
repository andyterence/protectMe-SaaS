from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from detection.models import AttackLog, ConnectionLog


class Command(BaseCommand):
    """Purge les ConnectionLog (et optionnellement les AttackLog deja
    requalifies) plus vieux que N jours. A planifier en cron cote serveur,
    aucune dependance supplementaire requise (pas de Celery/Redis) :

        0 3 * * * cd /path/to/backend && python manage.py cleanup_old_logs

    C'est le garde-fou de scalabilite pour ConnectionLog, qui grandit avec
    CHAQUE requete (contrairement a AttackLog, deja selectif par nature).
    """
    help = "Purge les logs de connexion (et attaques deja traitees) au-dela de N jours."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=30)

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=options["days"])

        deleted_connections, _ = ConnectionLog.objects.filter(created_at__lt=cutoff).delete()

        # Les AttackLog encore 'pending_review' sont conserves indefiniment
        # (un humain doit les traiter) ; seuls ceux deja requalifies sont
        # purgeables sans perte d'information utile au reentrainement.
        deleted_attacks, _ = AttackLog.objects.filter(
            created_at__lt=cutoff
        ).exclude(status=AttackLog.Status.PENDING).delete()

        self.stdout.write(self.style.SUCCESS(
            f"Purge terminee : {deleted_connections} ConnectionLog, {deleted_attacks} AttackLog traites."
        ))
