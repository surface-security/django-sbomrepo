import itertools
import json
import logging
from typing import Iterator
from urllib.parse import unquote

import requests

logger = logging.getLogger(__name__)


def chunked_iterable(iterable, size: int):
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk


def get_osv_ecosystems(short: bool = False) -> list[str]:
    """Get list of OSV ecosystems, optionally shortened."""
    try:
        res = requests.get(
            "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt",
            timeout=30
        )
        res.raise_for_status()
        ecosystems = res.text.splitlines()
        if short:
            ecosystems = [eco.split(":")[0] for eco in ecosystems]
        return sorted(set(ecosystems), key=str.casefold)
    except requests.RequestException as e:
        logger.error(f"Failed to fetch OSV ecosystems: {e}")
        return []


Query = dict[str, dict[str, str]]
Vuln = dict[str, str]
Purl = str


def get_osv_vulns(initial_queries: list[Query]) -> Iterator[tuple[Purl, list[Vuln]]]:
    """Query OSV API for vulnerabilities, handling pagination."""
    session = requests.Session()
    try:
        for chunk_queries in chunked_iterable(initial_queries, 1000):
            stack = [chunk_queries]

            while stack:
                queries = stack.pop()

                try:
                    res = session.post(
                        "https://api.osv.dev/v1/querybatch",
                        json={"queries": queries},
                        timeout=60
                    )
                    res.raise_for_status()
                except requests.RequestException as e:
                    logger.error("Bad response in osv.dev querybatch: %s", e)
                    continue

                try:
                    results = res.json()["results"]
                except (KeyError, json.JSONDecodeError) as e:
                    logger.error("Invalid JSON response from OSV API: %s", e)
                    continue

                for idx, result in enumerate(results):
                    if vulns := result.get("vulns"):
                        yield queries[idx]["package"]["purl"], vulns

                    if "next_page_token" in result:
                        queries[idx]["page_token"] = result["next_page_token"]
                        if stack:
                            stack[0].append(queries[idx])
                        else:
                            stack.append([queries[idx]])
    finally:
        session.close()


def cleanup_purl(purl: str) -> str:
    # Decode URL-encoded characters
    purl = unquote(purl)

    # cdxgen is listing dependencies with full path inside node_modules
    if purl.startswith("pkg:npm/") and "node_modules/" in purl:
        purl = f"pkg:npm/{purl.split('node_modules/')[1]}"

    return purl


def cleanup_sbom(sbom_data):
    for component in sbom_data.get("components", []):
        component["purl"] = cleanup_purl(component.get("purl", ""))
        component["bom-ref"] = cleanup_purl(component.get("bom-ref", ""))

    for dependency in sbom_data.get("dependencies", []):
        dependency["ref"] = cleanup_purl(dependency.get("ref", ""))

        for i, val in enumerate(dependency.get("dependsOn", [])):
            dependency["dependsOn"][i] = cleanup_purl(val)

    return sbom_data


def cleanup_git_url(git_url: str) -> str:
    if git_url.startswith("git@"):
        git_url = "https://" + git_url.split("@")[1].replace(":", "/")

    return git_url.replace(".git", "")


def cleanup_branch(branch: str) -> str:
    return branch.replace("origin/", "").replace("*/", "")


def cleanup_image_ref(image_ref: str) -> str:
    """Clean up Docker/OCI image reference.
    
    Removes common prefixes and normalizes the format.
    """
    if image_ref.startswith("docker://"):
        image_ref = image_ref[9:]

    if image_ref.startswith("oci://"):
        image_ref = image_ref[6:]
    
    if image_ref.startswith("docker.io/") and image_ref.count("/") == 1:
        image_ref = image_ref.replace("docker.io/", "docker.io/library/", 1)
    
    return image_ref.strip()


def replace_purl(sbom_data, old_purl, new_purl):
    if "metadata" in sbom_data and "component" in sbom_data["metadata"]:
        if sbom_data["metadata"]["component"]["purl"] == old_purl:
            sbom_data["metadata"]["component"]["purl"] = new_purl
            sbom_data["metadata"]["component"]["bom-ref"] = new_purl

    for component in sbom_data.get("components", []):
        if component["purl"] == old_purl:
            component["purl"] = new_purl
            component["bom-ref"] = new_purl

    for dependency in sbom_data.get("dependencies", []):
        if dependency["ref"] == old_purl:
            dependency["ref"] = new_purl

        for i, val in enumerate(dependency.get("dependsOn", [])):
            if val == old_purl:
                dependency["dependsOn"][i] = new_purl

    return sbom_data
