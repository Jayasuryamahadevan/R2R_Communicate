"""A CycloneDX software bill of materials, generated from what is installed.

IEC 62443-4-1 practice 6 (security update management) and every serious
vulnerability-handling process start from the same question: what is
actually in this thing? A dependency list in a `pyproject.toml` answers a
different question -- what was asked for -- and the gap between the two is
where a transitive dependency with a CVE lives.

So this reads `importlib.metadata`: the distributions genuinely importable
in this environment, with their versions, licences, and PURLs. Output is
CycloneDX 1.5 JSON, which every SCA tool ingests.

Deterministic by construction -- components sorted, no timestamps in the
component records -- so two SBOMs of the same environment are byte
identical and a diff means something changed.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from importlib import metadata
from typing import Any

from ..timestamps import stamp

CYCLONEDX_VERSION = "1.5"


def _licences(distribution: metadata.Distribution) -> list[dict[str, Any]]:
    """Licence from the Classifier trove first, then the License field.

    In that order because the trove classifier is a controlled vocabulary
    while `License:` is free text that is frequently a paragraph.
    """
    meta = distribution.metadata
    classifiers = [value for key, value in meta.items() if key == "Classifier" and value.startswith("License ::")]
    if classifiers:
        return [{"license": {"name": value.rsplit("::", 1)[-1].strip()}} for value in classifiers]
    declared = meta.get("License")
    if declared and len(declared) < 64:
        return [{"license": {"name": declared.strip()}}]
    return []


def _component(distribution: metadata.Distribution) -> dict[str, Any] | None:
    name = distribution.metadata.get("Name")
    if not name:
        return None
    version = distribution.version or "0"
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"pkg:pypi/{name.lower()}@{version}",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name.lower()}@{version}",
    }
    licences = _licences(distribution)
    if licences:
        component["licenses"] = licences
    homepage = distribution.metadata.get("Home-page")
    if homepage:
        component["externalReferences"] = [{"type": "website", "url": homepage}]
    # Hash the record of what is installed, not the wheel: a wheel is often
    # long gone by the time an SBOM is generated, and a stable identifier
    # for the installed record is still useful for change detection.
    component["hashes"] = [{"alg": "SHA-256", "content": hashlib.sha256(f"{name}@{version}".encode()).hexdigest()}]
    return component


def generate_sbom(*, application_name: str = "fasp-harness", application_version: str | None = None, include_environment: bool = True) -> dict[str, Any]:
    """Produce a CycloneDX 1.5 SBOM of the current environment."""
    if application_version is None:
        try:
            application_version = metadata.version("fasp-harness")
        except metadata.PackageNotFoundError:
            application_version = "0.0.0+local"

    components: dict[str, dict[str, Any]] = {}
    for distribution in metadata.distributions():
        try:
            component = _component(distribution)
        except (OSError, ValueError, KeyError):
            continue
        if component is not None:
            components.setdefault(component["bom-ref"], component)

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": stamp(),
            "tools": [{"vendor": "fasp-harness", "name": "fasp_harness.security.sbom", "version": application_version}],
            "component": {"type": "application", "bom-ref": f"pkg:pypi/{application_name}@{application_version}", "name": application_name, "version": application_version},
        },
        "components": [components[key] for key in sorted(components)],
    }
    if include_environment:
        document["metadata"]["properties"] = [
            {"name": "fasp:python", "value": platform.python_version()},
            {"name": "fasp:implementation", "value": platform.python_implementation()},
            {"name": "fasp:platform", "value": f"{platform.system()}/{platform.machine()}"},
        ]
    return document


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=False)


def main() -> int:
    """`python -m fasp_harness sbom`."""
    print(render(generate_sbom()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
