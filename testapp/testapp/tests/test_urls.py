from django.test import TestCase
from sbomrepo import models

class URLTests(TestCase):
    def test_index_url(self):
        """
        Test the index URL.
        """
        response = self.client.get("/sbomrepo/")
        assert response.status_code == 200

    def test_valid_sbom_urls(self):
        """
        Create a test SBOM entry in the database, then test the SBOM URL with a valid ID, expecting a 200 response.
        """
        # '/sbomrepo/v1/sbom/<sbom_id>'
        test_sbom = models.SBOM.objects.create(
            version=1,
            metadata={},
            document={},
            serial_number="urn:uuid:17bf7882-58e2-41dd-aa43-cc04bcbb27a8"
        )

        response = self.client.get(f"/sbomrepo/v1/sbom/{test_sbom.serial_number}")
        assert response.status_code == 200

        response = self.client.get("/sbomrepo/v1/sbom/all")
        assert response.status_code == 200

    def test_sbom_base_url_without_serial_number(self):
        """
        Acessing /sbomrepo/v1/sbom without a serial_number would result in TypeError due to the view's requirements.
        """
        with self.assertRaises(TypeError):
            self.client.get("/sbomrepo/v1/sbom")

    def test_invalid_sbom_urls(self):
        """
        Test the SBOM URL with an invalid ID or without any URL, expecting a 404 response.
        """

        response = self.client.get("/sbomrepo/v1/sbom/non-existent-id")
        assert response.status_code == 404

    def test_vulnerability_url_valid_id(self):
        """
        Test the vulnerability URL with a valid ID, expecting a 200 response.
        """

        test_vulnerability = models.Vulnerability.objects.create(id="GHSA-83fm-w79m-64r5", ecosystem='', document={},)
        response = self.client.get(f"/sbomrepo/v1/vulnerability/{test_vulnerability.id}")
        assert response.status_code == 200

    def test_vulnerability_url_invalid_id(self):
        """
        Test the vulnerability URL with an invalid ID, expecting a 404 response.
        """
        response = self.client.get("/sbomrepo/v1/vulnerability/non-existent-id")
        assert response.status_code == 404

    def test_ecosystems_url(self):
        """
        Test the ecosystems URL.
        """
        response = self.client.get("/sbomrepo/v1/ecosystems")
        assert response.status_code == 200
