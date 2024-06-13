import json
import logging
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views import View
from django.views.decorators.http import require_GET, require_http_methods
from packageurl import PackageURL

from sbomrepo import models, utils

logger = logging.getLogger(__name__)


@require_GET
def index(request: HttpRequest) -> HttpResponse:
    return JsonResponse({"version": settings.SBOMREPO_VERSION})


@require_http_methods(["DELETE"])
def delete_sboms(request: HttpRequest) -> HttpResponse:
    keep = int(request.GET.get("keep", 5))  # Number of SBOMS to keep
    grouped_sboms = defaultdict(list)
    sboms = models.SBOM.objects.defer("document").filter(active=True).order_by("-created_at")
    for sbom in sboms:
        grouped_sboms[
            (sbom.metadata.get("entry", "def"), sbom.metadata["repo"], sbom.metadata.get("branch", "master"))
        ].append(sbom.serial_number)

    deactivated = 0
    for _, sbom_list in grouped_sboms.items():
        deactivated += (
            models.SBOM.objects.defer("document").filter(serial_number__in=sbom_list[keep:]).update(active=False)
        )  # Marks all Sboms that we don't want to keep as inactive.

    # Delete Inactive SBOMs older thatn 7 days
    deleted, _ = (
        models.SBOM.objects.defer("document")
        .filter(active=False, created_at__lte=timezone.now() - timezone.timedelta(days=7))
        .delete()
    )

    return JsonResponse({"deactivated": deactivated, "deleted": deleted}, safe=False)


@require_GET
def list_sboms(request: HttpRequest) -> HttpResponse:
    since_date = request.GET.get("since")
    format = request.GET.get("format", "simple")
    metadata_filters = {k: v for k, v in request.GET.items() if k.startswith("metadata__")}

    sboms = models.SBOM.objects.filter(active=True)

    if since_date:
        sboms = sboms.filter(updated_at__gte=since_date)

    if metadata_filters:
        sboms = sboms.filter(**metadata_filters)

    if format == "structured":
        fields = ["serial_number", "purl", "created_at", "updated_at", "metadata"]
        return JsonResponse(
            [{f: getattr(sbom, f) for f in fields} for sbom in sboms.only(*fields)],
            safe=False,
        )
    elif format == "simple":
        return JsonResponse(list(sboms.values_list("serial_number", flat=True)), safe=False)

    raise NotImplementedError(format)


def get_vulns_details(vulns: list[str]) -> list[dict]:
    vulnerabilities = []
    for vuln in models.Vulnerability.objects.filter(id__in=vulns):
        doc = vuln.document
        doc["sbomrepo"] = {"ecosystem": vuln.ecosystem, "created_at": vuln.created_at, "updated_at": vuln.updated_at}
        vulnerabilities.append(doc)
    return vulnerabilities


def merge_duplicate_dependencies(data: list[dict]) -> list[dict]:
    merged_data = {}
    for item in data:
        ref = item["ref"]
        depends_on = item["dependsOn"]
        if ref not in merged_data:
            merged_data[ref] = depends_on
        else:
            merged_data[ref].extend(depends_on)

    merged_list = [{"ref": ref, "dependsOn": depends_on} for ref, depends_on in merged_data.items()]
    return merged_list


def purl_from_repo(repo: str, branch: str = "master") -> str:
    parsed_url = urlparse(repo)
    path_segments = parsed_url.path.strip("/").split("/", 1)

    # Extract host, namespace, and name
    git_host = parsed_url.netloc
    git_namespace = path_segments[0]
    git_name = path_segments[1]

    # Create a Package URL for the Git repository
    purl = PackageURL(
        type=git_host,
        namespace=git_namespace,
        name=git_name,
        version=branch,
        subpath="",
    )

    return PackageURL.to_string(purl)


@require_GET
def get_vulnerability(request: HttpRequest, id: str) -> HttpResponse:
    vuln = get_object_or_404(models.Vulnerability, pk=id)
    doc = vuln.document
    doc["sbomrepo"] = {"ecosystem": vuln.ecosystem, "created_at": vuln.created_at, "updated_at": vuln.updated_at}
    return JsonResponse(doc)


@require_GET
def get_ecosystems(request: HttpRequest) -> HttpResponse:
    return JsonResponse(utils.get_osv_ecosystems(not request.GET.get("full", False)), safe=False)


@require_GET  # should this be a get? it can update objects
def reimport_sbom(request: HttpRequest, serial_number: str) -> HttpResponse:
    sbom = get_object_or_404(models.SBOM, pk=serial_number)

    sbom, created = import_sbom(sbom.document, sbom.metadata)
    return JsonResponse({"serial_number": sbom.serial_number, "purl": sbom.purl, "created": created})


class SBOMView(View):
    def get(self, request: HttpRequest, serial_number: str) -> HttpResponse:
        sbom = get_object_or_404(models.SBOM, pk=serial_number)
        doc = sbom.document
        doc["sbomrepo"] = {"metadata": sbom.metadata}

        if request.GET.get("vuln_data", False):
            doc["sbomrepo"]["vulnerabilities"] = defaultdict(list)

            queries = []
            for p in doc.get("components", []):
                queries.append({"package": {"purl": p["purl"]}})

            for purl, vulns in utils.get_osv_vulns(queries):
                doc["sbomrepo"]["vulnerabilities"][purl].extend(get_vulns_details(vulns=[vuln["id"] for vuln in vulns]))

        return JsonResponse(doc)

    def post(self, request: HttpRequest) -> HttpResponse:
        if request.content_type == "multipart/form-data":
            sbom_data = json.load(request.FILES["file"].file)
        else:
            sbom_data = json.loads(request.body)

        metadata = {k: v[0] for k, v in dict(request.GET).items()}

        sbom, created = import_sbom(sbom_data, metadata)
        return JsonResponse({"serial_number": sbom.serial_number, "purl": sbom.purl, "created": created})


def import_sbom(sbom_data: dict[str, Any], metadata: dict[str, str]) -> tuple[models.SBOM, bool]:
    sbom_data = utils.cleanup_sbom(sbom_data)

    if "repo" in metadata:
        metadata["repo"] = utils.cleanup_git_url(metadata["repo"])

    if "branch" in metadata:
        metadata["branch"] = utils.cleanup_branch(metadata["branch"])

    if "main_branch" in metadata:
        metadata["main_branch"] = utils.cleanup_branch(metadata["main_branch"])

    purl = purl_from_repo(metadata["repo"], metadata["branch"])
    original_purl = sbom_data.get("metadata", {}).get("component", {}).get("purl")

    if "metadata" in sbom_data:
        original_purl_obj = None
        try:
            original_purl_obj = PackageURL.from_string(original_purl)
        except ValueError as e:
            logger.warning(f"Invalid purl format or error in creating PackageURL: {original_purl} - Error: {str(e)}")

        if original_purl and original_purl_obj and original_purl_obj.name == "app":
            utils.replace_purl(sbom_data, original_purl, purl)
        else:
            sbom_data["dependencies"].append({"ref": purl, "dependsOn": [original_purl]})
            purl = original_purl

    primary_deps = set()
    secundary_deps = set()

    for dependency in sbom_data.get("dependencies", []):
        if dependency.get("ref") and PackageURL.from_string(dependency["ref"]).name == "app":
            utils.replace_purl(sbom_data, dependency["ref"], purl)

        primary_deps.add(dependency["ref"])
        secundary_deps.update(dependency.get("dependsOn", []))

    # Merge duplicate dependencies created by replace_purl
    sbom_data["dependencies"] = merge_duplicate_dependencies(sbom_data.get("dependencies", []))

    missing_dependencies = primary_deps - secundary_deps
    if missing_dependencies and purl in missing_dependencies:
        missing_dependencies.remove(purl)
        for dep in sbom_data.get("dependencies", []):
            if dep["ref"] == purl:
                dep["dependsOn"].extend(missing_dependencies)

    version = sbom_data.get("metadata", {}).get("component", {}).get("version", sbom_data.get("version", "1"))

    sbom, created = models.SBOM.objects.update_or_create(
        serial_number=sbom_data["serialNumber"],
        defaults={
            "purl": purl.split("?")[0],  # ignore optional qualifiers
            "type": sbom_data.get("metadata", {}).get("component", {}).get("type", "application"),
            "version": version,
            "document": sbom_data,
            "metadata": metadata,
        },
    )

    return sbom, created
