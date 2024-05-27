import json
from io import BytesIO
from unittest.mock import patch
from zipfile import ZipFile, ZipInfo

import responses
from django.core.management import call_command
from django.test import TestCase

from sbomrepo import models


class CommandTestCase(TestCase):
    @responses.activate
    def test_command_unzip_and_bulk_create(self):
        # Example JSON data to be included in the mocked zip file
        example_json_data = {
            "id": "GSD-2022-1000008",
            "summary": "faker.js 6.6.6 is broken and the developer has wiped the original GitHub repo",
            "details": "faker.js had it's version updated to 6.6.6 in NPM...",
        }

        # Simulate downloading a zip file containing the example JSON and mock it
        zipped_data = BytesIO()
        with ZipFile(zipped_data, 'w') as zf:
            zip_info = ZipInfo('example.json')
            # Important: adjust the date and time to avoid timezone issues in tests
            zip_info.date_time = (2022, 1, 9, 11, 37, 1)
            zf.writestr(zip_info, bytes(json.dumps(example_json_data), 'utf-8'))
        zipped_data.seek(0)

        # Use responses to mock the HTTP GET request
        responses.add(responses.GET, 'https://osv-vulnerabilities.storage.googleapis.com/example-ecosystem/all.zip',
                      body=zipped_data.getvalue(), status=200, content_type='application/zip')

        # Mock get_osv_ecosystems to return a predictable list
        with patch('sbomrepo.utils.get_osv_ecosystems', return_value=['example-ecosystem']):
            # Mock the bulk_create
            with patch.object(models.Vulnerability.objects, 'bulk_create', wraps=models.Vulnerability.objects.bulk_create) as mock_bulk_create:
                call_command('resync_vulnerabilities')

                # Check that bulk_create was called once with the correct data
                mock_bulk_create.assert_called_once()
                call_args = mock_bulk_create.call_args[0][0]  # This should be the list of vulnerabilities
                assert len(call_args) == 1  # Expecting one vulnerability object
                vuln = call_args[0]
                assert isinstance(vuln, models.Vulnerability)
                assert vuln.id == "GSD-2022-1000008"
                assert vuln.ecosystem == "example-ecosystem"
                assert vuln.document == example_json_data
