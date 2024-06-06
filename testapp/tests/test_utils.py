import json
import os

import responses
from django.test import TestCase
from responses.registries import OrderedRegistry

from sbomrepo import utils


class TestUtils(TestCase):
    def test_chunked_iterable(self):
        some_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

        res = list(utils.chunked_iterable(some_list, 4))
        assert res == [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10]]

    @responses.activate
    def test_get_ocsv_ecosystems(self):
        with open(os.path.join(os.path.dirname(__file__), "data/ecosystems.txt"), "rb") as f:
            responses.get("https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt", body=f.read())

        assert utils.get_osv_ecosystems(short=False) == ["AlmaLinux", "AlmaLinux:8", "GitHub Actions", "npm"]

        assert utils.get_osv_ecosystems(short=True) == ["AlmaLinux", "GitHub Actions", "npm"]

    @responses.activate
    def test_get_osv_vulns(self):
        with open(os.path.join(os.path.dirname(__file__), "data/querybatch1.json"), "rb") as f:
            responses.post("https://api.osv.dev/v1/querybatch", json=json.load(f))

        result = list(
            utils.get_osv_vulns(
                [
                    {"package": {"purl": "pkg:npm/ampproject/remapping@2.2.0"}},
                    {"package": {"purl": "pkg:pypi/mlflow@0.4.0"}},
                ]
            )
        )

        assert result == [
            (
                "pkg:pypi/mlflow@0.4.0",
                [
                    {"id": "GHSA-83fm-w79m-64r5", "modified": "2023-05-01T14:11:48.080729Z"},
                    {"id": "PYSEC-2023-70", "modified": "2023-06-05T01:12:55.587142Z"},
                ],
            )
        ]

    @responses.activate(registry=OrderedRegistry)
    def test_get_osv_vulns_pagination(self):
        responses.add(
            "POST",
            "https://api.osv.dev/v1/querybatch",
            json={
                "results": [
                    {},
                    {
                        "vulns": [{"id": "PYSEC-2014-82", "modified": "2023-05-01T14:11:48.080729Z"}],
                    },
                    {
                        "vulns": [
                            {"id": "GHSA-83fm-w79m-64r5", "modified": "2023-05-01T14:11:48.080729Z"},
                            {"id": "PYSEC-2023-70", "modified": "2023-06-05T01:12:55.587142Z"},
                        ],
                        "next_page_token": "token1",
                    },
                    {
                        "vulns": [
                            {"id": "GHSA-83fm-w79m-64r6", "modified": "2023-05-01T14:11:48.080729Z"},
                            {"id": "PYSEC-2023-79", "modified": "2023-06-05T01:12:55.587142Z"},
                        ],
                        "next_page_token": "token2",
                    },
                ]
            },
        )

        responses.add(
            "POST",
            "https://api.osv.dev/v1/querybatch",
            json={"results": [{"vulns": [{"id": "PYSEC-2023-71", "modified": "2023-06-05T01:12:55.587142Z"}]}]},
        )

        result = list(
            utils.get_osv_vulns(
                [
                    {"package": {"purl": "pkg:npm/something/else@1.2.3"}},
                    {"package": {"purl": "pkg:npm/ampproject/remapping@2.2.0"}},
                    {"package": {"purl": "pkg:pypi/mlflow@0.4.0"}},
                    {"package": {"purl": "pkg:pypi/mlflow@0.4.2"}},
                ],
            )
        )

        assert result == [
            (
                "pkg:npm/ampproject/remapping@2.2.0",
                [{"id": "PYSEC-2014-82", "modified": "2023-05-01T14:11:48.080729Z"}],
            ),
            (
                "pkg:pypi/mlflow@0.4.0",
                [
                    {"id": "GHSA-83fm-w79m-64r5", "modified": "2023-05-01T14:11:48.080729Z"},
                    {"id": "PYSEC-2023-70", "modified": "2023-06-05T01:12:55.587142Z"},
                ],
            ),
            (
                "pkg:pypi/mlflow@0.4.2",
                [
                    {"id": "GHSA-83fm-w79m-64r6", "modified": "2023-05-01T14:11:48.080729Z"},
                    {"id": "PYSEC-2023-79", "modified": "2023-06-05T01:12:55.587142Z"},
                ],
            ),
            (
                "pkg:pypi/mlflow@0.4.0",
                [
                    {"id": "PYSEC-2023-71", "modified": "2023-06-05T01:12:55.587142Z"},
                ],
            ),
        ]

    def test_cleanup_purl(self):
        original_purls = [
            "pkg:npm/node_modules/somepackage",
            "pkg:npm/%40angular/core@12.0.0",
        ]
        expected_purls = [
            "pkg:npm/somepackage",
            "pkg:npm/@angular/core@12.0.0",
        ]
        cleaned_purls = [utils.cleanup_purl(purl) for purl in original_purls]
        assert cleaned_purls == expected_purls, "cleanup_purl did not clean the purls as expected."

    def test_cleanup_sbom(self):
        sbom_data = {
            "components": [{"purl": "pkg:npm/node_modules/somepackage", "bom-ref": "pkg:npm/node_modules/somepackage"}],
            "dependencies": [
                {"ref": "pkg:npm/node_modules/somepackage", "dependsOn": ["pkg:npm/node_modules/somepackage"]}
            ],
        }
        expected_cleaned_data = {
            "components": [{"purl": "pkg:npm/somepackage", "bom-ref": "pkg:npm/somepackage"}],
            "dependencies": [{"ref": "pkg:npm/somepackage", "dependsOn": ["pkg:npm/somepackage"]}],
        }
        cleaned_data = utils.cleanup_sbom(sbom_data)

        assert cleaned_data == expected_cleaned_data, "SBOM data was not cleaned up as expected."

    def test_cleanup_git_url(self):
        assert utils.cleanup_git_url("https://github.com/torvalds/linux.git") == "https://github.com/torvalds/linux"
        assert utils.cleanup_git_url("git@github.com:torvalds/linux.git") == "https://github.com/torvalds/linux"

    def test_cleanup_branch(self):
        assert utils.cleanup_branch("master") == "master"
        assert utils.cleanup_branch("origin/main") == "main"
        assert utils.cleanup_branch("*/feature-1234") == "feature-1234"

    def test_replace_purl(self):
        sbom_data = {
            "metadata": {"component": {"purl": "old_purl", "bom-ref": "old_purl"}},
            "components": [{"purl": "old_purl", "bom-ref": "old_purl"}],
            "dependencies": [{"ref": "old_purl", "dependsOn": ["old_purl"]}],
        }
        new_purl = "new_purl"
        expected_data = {
            "metadata": {"component": {"purl": "new_purl", "bom-ref": "new_purl"}},
            "components": [{"purl": "new_purl", "bom-ref": "new_purl"}],
            "dependencies": [{"ref": "new_purl", "dependsOn": ["new_purl"]}],
        }
        updated_data = utils.replace_purl(sbom_data, "old_purl", new_purl)

        assert (
            updated_data == expected_data
        ), "Not all instances of the old purl were replaced with the new purl as expected."
