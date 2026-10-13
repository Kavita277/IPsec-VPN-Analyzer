"""Policy loading and validation.

A policy is a JSON document that lists, per parameter, which values are
forbidden, deprecated, or approved. Rules read policies; they never hard-code
algorithm lists, so the same session can be assessed under different policies.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from assessment.models import Severity

POLICY_DIR = Path(__file__).resolve().parent / "policies"
PARAMETERS = ("encryption", "integrity", "dh_group")
TIERS = ("forbidden", "deprecated", "approved")


class PolicyError(ValueError):
    """Raised when a policy file is missing or malformed."""


class Policy:
    def __init__(self, data: Dict[str, Any]) -> None:
        self.data = data
        self.policy_id: str = data["policy_id"]
        self.name: str = data["name"]
        self.version: str = data["version"]

    def section(self, parameter: str) -> Dict[str, List[str]]:
        raw = self.data.get(parameter, {})
        return {tier: list(raw.get(tier, [])) for tier in TIERS}

    @property
    def ike_versions(self) -> List[str]:
        return list(self.data.get("ike_versions", []))

    @property
    def recommended(self) -> Dict[str, str]:
        return dict(self.data.get("recommended", {}))

    @property
    def references(self) -> List[str]:
        return list(self.data.get("references", []))

    def severity_for(self, finding_id: str, default: Severity) -> Severity:
        override = self.data.get("severities", {}).get(finding_id)
        return Severity.from_label(override) if override else default

    def summary(self) -> Dict[str, str]:
        return {"id": self.policy_id, "name": self.name, "version": self.version}


def validate_policy(data: Any) -> None:
    if not isinstance(data, dict):
        raise PolicyError("Policy must be a JSON object")
    for key in ("policy_id", "name", "version"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise PolicyError(f"Policy is missing required string field {key!r}")
    for parameter in PARAMETERS:
        section = data.get(parameter)
        if not isinstance(section, dict):
            raise PolicyError(f"Policy {data['policy_id']!r} needs a {parameter!r} section")
        for tier in TIERS:
            values = section.get(tier, [])
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise PolicyError(f"{parameter}.{tier} must be a list of strings")
        overlap = set(section.get("forbidden", [])) & set(section.get("approved", []))
        if overlap:
            raise PolicyError(f"{parameter}: {sorted(overlap)} cannot be both forbidden and approved")
    versions = data.get("ike_versions")
    if not isinstance(versions, list) or not versions:
        raise PolicyError("ike_versions must be a non-empty list")
    for finding_id, label in data.get("severities", {}).items():
        try:
            Severity.from_label(label)
        except ValueError as exc:
            raise PolicyError(f"severities[{finding_id}]: {exc}") from None


def list_policies() -> List[str]:
    return sorted(p.stem for p in POLICY_DIR.glob("*.json"))


def load_policy(name_or_path: Union[str, Path, Policy, None] = None) -> Policy:
    """Load a bundled policy by id (default: nist-baseline) or a JSON file by path."""
    if isinstance(name_or_path, Policy):
        return name_or_path
    ref = str(name_or_path) if name_or_path else "nist-baseline"
    path = POLICY_DIR / f"{ref}.json"
    if not path.is_file():
        path = Path(ref)
    if not path.is_file():
        raise PolicyError(f"Unknown policy {ref!r}. Bundled policies: {', '.join(list_policies())}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"Policy file {path} is not valid JSON: {exc}") from None
    validate_policy(data)
    return Policy(data)
