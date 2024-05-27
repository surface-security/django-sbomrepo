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
    def handle(self, *args: Any, **options: Any) -> str | None:
        session = requests.Session()

        ecosystems = get_osv_ecosystems()

        for ecosystem in tqdm(ecosystems):
            z = session.get(f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip")

            vulns = []

            with ZipFile(BytesIO(z.content)) as zipfile:
                for file_name in zipfile.namelist():
                    with zipfile.open(file_name) as f:
                        j = json.load(f)
                        vulns.append(Vulnerability(id=j["id"], ecosystem=ecosystem, document=j))

            Vulnerability.objects.bulk_create(
                vulns, update_conflicts=True, unique_fields=["id"], update_fields=["document"], batch_size=100
            )
