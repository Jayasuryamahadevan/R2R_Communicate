"""Industrial cybersecurity as a workflow, not a paragraph.

"Certification" is not something software can grant itself, and this
package does not pretend to. What it can do is the part that is genuinely
mechanical, and that a certification process will ask for anyway:

- `iec62443`  a control register mapped to IEC 62443-3-3's foundational
              requirements, where each control is *evaluated against the
              running configuration* rather than ticked in a spreadsheet.
              Plus the 62443-3-2 zone-and-conduit model, so a deployment
              states where its trust boundaries are and gets told when a
              conduit crosses between mismatched security levels.
- `posture`   a deployment profile that refuses to start insecurely.
              `production` is not advice; it is a precondition, and a
              violating configuration exits rather than logging a warning.
- `sbom`      a CycloneDX software bill of materials, because vulnerability
              handling (62443-4-1 practice 6) is impossible without knowing
              what is installed.

The honest framing throughout: this produces the *evidence* an assessment
consumes. The assessment is done by people.
"""

from __future__ import annotations

from .iec62443 import Conduit, ControlResult, SecurityAssessment, SecurityLevel, SystemContext, Zone, default_register
from .posture import DeploymentConfig, PostureReport, SecurityProfile, evaluate_posture
from .sbom import generate_sbom

__all__ = [
    "Conduit",
    "ControlResult",
    "DeploymentConfig",
    "PostureReport",
    "SecurityAssessment",
    "SecurityLevel",
    "SecurityProfile",
    "SystemContext",
    "Zone",
    "default_register",
    "evaluate_posture",
    "generate_sbom",
]
