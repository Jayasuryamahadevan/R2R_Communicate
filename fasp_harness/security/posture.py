"""A deployment profile that refuses to start insecurely.

The reason this is a hard gate rather than a warning is empirical: every
insecure industrial deployment was configured by someone who intended to
fix it later. A warning at startup is read once, by the person who already
knows. An exit is read by whoever is trying to deploy.

Three profiles:

    development  loopback, plain HTTP, no client certificates. Fine on a
                 laptop; the profile records that it is not a deployment.
    hardened     TLS required, no default credentials, rate limits set,
                 private material 0600. The floor for anything on a real
                 network.
    production   hardened, plus mutual TLS, plus an enforcing ROS 2
                 security posture, plus a verified audit chain at boot.

Every check returns a remediation string. A gate that tells you what is
wrong without telling you what to do is a gate people disable.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..protocol.errors import FaspError


class SecurityProfile(StrEnum):
    DEVELOPMENT = "development"
    HARDENED = "hardened"
    PRODUCTION = "production"

    @property
    def rank(self) -> int:
        return {SecurityProfile.DEVELOPMENT: 0, SecurityProfile.HARDENED: 1, SecurityProfile.PRODUCTION: 2}[self]


@dataclass
class DeploymentConfig:
    """Everything the posture checks need to know about how this is running."""

    profile: SecurityProfile = SecurityProfile.DEVELOPMENT
    host: str = "127.0.0.1"
    tls_cert: Path | None = None
    tls_key: Path | None = None
    tls_client_ca: Path | None = None
    insecure_http: bool = False
    state_dir: Path = field(default_factory=lambda: Path(".fasp"))
    rate_limit_per_peer: float = 10.0
    ip_rate_limit_per_second: float = 20.0
    max_inflight_tasks: int = 256
    ros2_enabled: bool = False
    ros2_posture: Any = None
    audit_verified: bool | None = None
    artifact_encryption: bool = False
    behind_reverse_proxy: bool = False
    safety_controller: dict[str, Any] | None = None

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_cert and self.tls_key)

    @property
    def mtls_enabled(self) -> bool:
        return bool(self.tls_client_ca and self.tls_enabled)

    @property
    def loopback_only(self) -> bool:
        return self.host in {"127.0.0.1", "localhost", "::1"}


@dataclass
class PostureFinding:
    control: str
    severity: str
    detail: str
    remediation: str
    required_from: SecurityProfile

    @property
    def blocking(self) -> bool:
        return self.severity in {"critical", "high"}

    def to_dict(self) -> dict[str, Any]:
        return {"control": self.control, "severity": self.severity, "detail": self.detail, "remediation": self.remediation, "required_from": self.required_from.value}


@dataclass
class PostureReport:
    profile: SecurityProfile
    findings: list[PostureFinding]

    @property
    def blocking(self) -> list[PostureFinding]:
        return [finding for finding in self.findings if finding.blocking and self.profile.rank >= finding.required_from.rank]

    @property
    def acceptable(self) -> bool:
        return not self.blocking

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "acceptable": self.acceptable,
            "blocking": [finding.to_dict() for finding in self.blocking],
            "advisory": [finding.to_dict() for finding in self.findings if finding not in self.blocking],
        }

    def render_text(self) -> str:
        lines = [f"Security posture: {self.profile.value}", "=" * (18 + len(self.profile.value)), ""]
        if not self.findings:
            lines.append("No findings.")
        for finding in sorted(self.findings, key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item.severity, 4)):
            marker = "BLOCK" if finding in self.blocking else " note"
            lines.append(f"[{marker}] {finding.severity:8} {finding.control}: {finding.detail}")
            if finding.remediation:
                lines.append(f"                  -> {finding.remediation}")
        lines += ["", f"VERDICT: {'acceptable' if self.acceptable else 'REFUSED -- ' + str(len(self.blocking)) + ' blocking finding(s)'}"]
        return "\n".join(lines)

    def enforce(self) -> None:
        if not self.acceptable:
            detail = "; ".join(f"{finding.control}: {finding.detail}" for finding in self.blocking[:4])
            raise FaspError("policy.insecure_configuration", f"Refusing to start in the {self.profile.value} profile: {detail}")


Check = Callable[[DeploymentConfig], list[PostureFinding]]


def _finding(control: str, severity: str, detail: str, remediation: str, required_from: SecurityProfile) -> PostureFinding:
    return PostureFinding(control, severity, detail, remediation, required_from)


def _check_transport(config: DeploymentConfig) -> list[PostureFinding]:
    findings: list[PostureFinding] = []
    if not config.tls_enabled and not config.behind_reverse_proxy:
        severity = "critical" if not config.loopback_only else "medium"
        findings.append(_finding("transport.tls", severity, "Signed envelopes are being carried over plain HTTP, so peer identity is authenticated but traffic is readable and correlatable on the wire.", "Supply --tls-cert/--tls-key, or terminate TLS at a reverse proxy and set behind_reverse_proxy.", SecurityProfile.HARDENED))
    if config.insecure_http and not config.loopback_only:
        findings.append(_finding("transport.insecure_http", "high", "--insecure-http is set on a non-loopback interface.", "Remove --insecure-http and configure TLS.", SecurityProfile.HARDENED))
    if not config.mtls_enabled:
        findings.append(_finding("transport.mtls", "high", "Client certificates are not required, so anything that can reach the port can attempt an envelope and consume rate-limit budget.", "Supply --tls-client-ca to require and verify client certificates.", SecurityProfile.PRODUCTION))
    return findings


def _check_secrets(config: DeploymentConfig) -> list[PostureFinding]:
    findings: list[PostureFinding] = []
    for name, description in (("identity.json", "Ed25519 private key"), ("admin_token", "local administrator token")):
        path = config.state_dir / name
        if not path.exists():
            continue
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            continue
        if mode & 0o077:
            findings.append(_finding("secrets.permissions", "critical", f"The {description} at {name} is mode {mode:o}: readable by users other than its owner.", f"chmod 600 {path}", SecurityProfile.HARDENED))
    if os.environ.get("FASP_ADMIN_TOKEN"):
        findings.append(_finding("secrets.environment", "medium", "An admin token is present in the environment, where it is visible to any process that can read /proc and to most container inspection tooling.", "Use the on-disk 0600 token file instead.", SecurityProfile.HARDENED))
    return findings


def _check_limits(config: DeploymentConfig) -> list[PostureFinding]:
    findings: list[PostureFinding] = []
    if config.rate_limit_per_peer <= 0 or config.ip_rate_limit_per_second <= 0:
        findings.append(_finding("availability.rate_limits", "high", "Rate limiting is disabled, so one peer or one address can consume the whole service.", "Set positive --rate-limit-per-peer and --ip-rate-limit-per-second values.", SecurityProfile.HARDENED))
    if config.max_inflight_tasks <= 0 or config.max_inflight_tasks > 10_000:
        findings.append(_finding("availability.queue_depth", "medium", f"max_inflight_tasks is {config.max_inflight_tasks}, which does not bound the backlog usefully.", "Set a queue depth the host can actually service.", SecurityProfile.HARDENED))
    return findings


def _check_ros2(config: DeploymentConfig) -> list[PostureFinding]:
    if not config.ros2_enabled:
        return []
    posture = config.ros2_posture
    if posture is None:
        from ..industrial.ros2 import inspect_sros2

        posture = inspect_sros2()
    return [
        _finding(f"ros2.{finding.control}", finding.severity, finding.detail, finding.remediation, SecurityProfile.HARDENED)
        for finding in getattr(posture, "findings", [])
    ]


def _check_audit(config: DeploymentConfig) -> list[PostureFinding]:
    if config.audit_verified is False:
        return [_finding("audit.integrity", "critical", "The hash-chained audit log failed verification at startup, so its history cannot be relied on.", "Investigate before accepting traffic; a broken chain means tampering or corruption.", SecurityProfile.HARDENED)]
    if config.audit_verified is None:
        return [_finding("audit.integrity", "low", "The audit chain was not verified at startup.", "Verify it during startup so tampering is detected at the earliest point.", SecurityProfile.PRODUCTION)]
    return []


def _check_data_at_rest(config: DeploymentConfig) -> list[PostureFinding]:
    if config.artifact_encryption:
        return []
    return [_finding("data.at_rest", "medium", "Artifacts are stored unencrypted on disk; anything a peer sends that gets materialised as an artifact is readable from a backup or a stolen device.", "Use full-disk or filesystem-level encryption on the state directory.", SecurityProfile.PRODUCTION)]


def _check_safety_controller(config: DeploymentConfig) -> list[PostureFinding]:
    controller = config.safety_controller
    if controller is None:
        return []
    if not controller.get("real_hardware", False):
        return [_finding("safety.controller", "critical", "The configured safety controller is a simulation, which carries no safety integrity whatsoever.", "Configure a real, certified safety controller before any deployment with physical actuation.", SecurityProfile.HARDENED)]
    return []


CHECKS: tuple[Check, ...] = (_check_transport, _check_secrets, _check_limits, _check_ros2, _check_audit, _check_data_at_rest, _check_safety_controller)


def evaluate_posture(config: DeploymentConfig) -> PostureReport:
    """Run every check against this configuration."""
    findings: list[PostureFinding] = []
    for check in CHECKS:
        findings.extend(check(config))
    return PostureReport(profile=config.profile, findings=findings)
