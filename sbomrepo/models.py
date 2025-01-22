from django.core.serializers.json import DjangoJSONEncoder
from django.db import models


class SBOM(models.Model):
    serial_number = models.CharField(primary_key=True, max_length=255)  # URN
    purl = models.CharField(max_length=255)  # https://github.com/package-url/purl-spec
    type = models.CharField(max_length=63)
    version = models.CharField(max_length=127)
    document = models.JSONField(encoder=DjangoJSONEncoder)
    metadata = models.JSONField(encoder=DjangoJSONEncoder)

    active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["created_at"]


class Vulnerability(models.Model):
    id = models.CharField(primary_key=True, max_length=128)
    ecosystem = models.CharField(max_length=255)
    document = models.JSONField(encoder=DjangoJSONEncoder)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"f{self.ecosystem}/{self.id}"
