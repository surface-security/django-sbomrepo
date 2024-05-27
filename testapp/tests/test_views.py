import json
from unittest import mock

from django.test import RequestFactory, TestCase
import os
from sbomrepo.models import SBOM, Vulnerability
from sbomrepo.views import (
    SBOMView,
)


class ViewsTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

        print(os.path.join(os.path.dirname(__file__), "examples/tiny.json"))
        with open(os.path.join(os.path.dirname(__file__), "examples/tiny.json")) as f:
            SBOM.objects.create(version=1, metadata={}, document=json.load(f), serial_number="123")

        Vulnerability.objects.create(id="GHSA-83fm-w79m-64r5", ecosystem="", document={"id": "GHSA-83fm-w79m-64r5"})
        Vulnerability.objects.create(id="PYSEC-2023-70", ecosystem="", document={"id": "PYSEC-2023-70"})
        Vulnerability.objects.create(id="PYSEC-2023-79", ecosystem="", document={"id": "PYSEC-2023-79"})

    @mock.patch(
        "sbomrepo.utils.get_osv_vulns",
        return_value=[
            (
                "pkg:lib/acme-library@1.0.0",
                [
                    {"id": "GHSA-83fm-w79m-64r5", "modified": "2023-05-01T14:11:48.080729Z"},
                    {"id": "PYSEC-2023-70", "modified": "2023-06-05T01:12:55.587142Z"},
                ],
            ),
            (
                "pkg:lib/acme-library@1.0.0",
                [
                    {"id": "PYSEC-2023-79", "modified": "2023-06-05T01:12:55.587142Z"},
                ],
            ),
        ],
    )
    def test_SBOMView_get(self, mock_get_osv_vulns):
        view = SBOMView()
        request = self.factory.get("/sbomrepo/v1/sbom/123", data={"vuln_data": True})
        response = view.get(request, "123")

        sbom = json.loads(response.content)

        mock_get_osv_vulns.assert_called_once()
        assert response.status_code == 200
        assert len(sbom["sbomrepo"]["vulnerabilities"]["pkg:lib/acme-library@1.0.0"]) == 3
