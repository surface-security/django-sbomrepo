from django.apps import AppConfig
from django.conf import settings

APP_SETTINGS = dict(
    VERSION='0.0.8',
)

class SbomRepoConfig(AppConfig):
    name = 'sbomrepo'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self):
        for k, v in APP_SETTINGS.items():
            _k = 'SBOMREPO_%s' % k
            if hasattr(settings, _k):
                continue
            setattr(settings, _k, v)