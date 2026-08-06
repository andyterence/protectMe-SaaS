class ProtectMeConfigError(Exception):
    """Levée si la configuration Django est incomplète ou invalide.

    Volontairement bruyante : une mauvaise config (ex: clé API oubliée)
    doit planter au démarrage du serveur, pas silencieusement laisser
    passer tout le trafic sans protection.
    """


class ProtectMeDetectionError(Exception):
    """Levée en interne quand l'appel à l'API centrale échoue.

    Cette exception est toujours interceptée par le middleware lui-même
    (jamais propagée à la vue Django) : c'est la politique fail-open/
    fail-closed qui décide quoi faire ensuite, pas l'appelant.
    """
