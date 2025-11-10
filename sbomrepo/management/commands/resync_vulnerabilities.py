import json
from io import BytesIO
from typing import Any

import requests
from django.core.management.base import BaseCommand
from tqdm import tqdm
from zipfile import ZipFile

from sbomrepo.models import Vulnerability
from sbomrepo.utils import get_osv_ecosystems


class Command(BaseCommand):
    help = "Re-sync vulnerabilities from OSV database"

    def handle(self, *args: Any, **options: Any) -> None:
        session = requests.Session()
        ecosystems = get_osv_ecosystems()

        if not ecosystems:
            self.stdout.write(self.style.ERROR("No ecosystems found"))
            return

        total_processed = 0
        total_errors = 0

        for ecosystem in tqdm(ecosystems, desc="Processing ecosystems"):
            try:
                response = session.get(
                    f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip",
                    timeout=300
                )
                response.raise_for_status()
            except requests.RequestException as e:
                self.stdout.write(
                    self.style.WARNING(f"Failed to fetch {ecosystem}: {e}")
                )
                total_errors += 1
                continue

            try:
                with ZipFile(BytesIO(response.content)) as zipfile:
                    for file_name in zipfile.namelist():
                        try:
                            with zipfile.open(file_name) as f:
                                j = json.load(f)
                                if "id" not in j:
                                    continue
                                Vulnerability.objects.update_or_create(
                                    id=j["id"],
                                    defaults={
                                        "ecosystem": ecosystem,
                                        "document": j
                                    }
                                )
                                total_processed += 1
                        except (json.JSONDecodeError, KeyError) as e:
                            self.stdout.write(
                                self.style.WARNING(f"Error processing {file_name}: {e}")
                            )
                            total_errors += 1
                            continue
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error processing {ecosystem} zip: {e}")
                )
                total_errors += 1
                continue

        self.stdout.write(
            self.style.SUCCESS(
                f"Processed {total_processed} vulnerabilities. {total_errors} errors."
            )
        )
