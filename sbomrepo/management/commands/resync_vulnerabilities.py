import json
from io import BytesIO
from typing import Any
from zipfile import ZipFile

import requests
from django.core.management.base import BaseCommand
from tqdm import tqdm

from sbomrepo.models import Vulnerability
from sbomrepo.utils import get_osv_ecosystems


class Command(BaseCommand):
    def handle(self, *args: Any, **options: Any):
        session = requests.Session()

        ecosystems = get_osv_ecosystems()

        for ecosystem in tqdm(ecosystems):
            z = session.get(f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip")

            with ZipFile(BytesIO(z.content)) as zipfile:
                for file_name in zipfile.namelist():
                    with zipfile.open(file_name) as f:
                        j = json.load(f)
                        Vulnerability.objects.update_or_create(
                            id=j["id"],
                            defaults={
                                "ecosystem": ecosystem,
                                "document": j
                            }
                        )
