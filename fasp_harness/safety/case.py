"""A safety case you can run: GSN claims bound to executable evidence.

A safety case is an argument that a system is acceptably safe in a defined
context, supported by evidence. Written as a document, its failure mode is
that it drifts: the argument stays confident while the system underneath it
changes. Written like this, it cannot -- every leaf of the argument is a
callable that either produces evidence right now or does not, and the
verdict is recomputed from the leaves every time it is asked for.

The structure follows Goal Structuring Notation, because it is the
notation an assessor will already know:

    Goal        a claim: "the coordinator cannot defeat a protective stop"
    Strategy    how the claim is argued into sub-claims
    Context     what the claim is scoped to
    Assumption  what is taken as given (and by whom)
    Solution    the evidence that discharges a claim
    Undeveloped a claim deliberately not argued here (GSN's diamond)

Two verdicts exist that a paper case usually elides, and both are load
bearing:

    DELEGATED   this claim is Layer 1's, discharged by a certified device
                and its own assessment. This software does not argue it and
                must not appear to. Delegation is *recorded*, with who owns
                it, not silently omitted.
    UNDEVELOPED this claim is not argued at all yet.

`SafetyCaseReport.certifiable` is therefore always False in this
repository, and `verdict` can never be better than "argued, not
independently assessed". Independent assessment is a thing a person does;
no function can return it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from ..timestamps import stamp


class Verdict(StrEnum):
    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    INCONCLUSIVE = "inconclusive"
    DELEGATED = "delegated"
    UNDEVELOPED = "undeveloped"
    NOT_APPLICABLE = "not_applicable"

    @property
    def is_failure(self) -> bool:
        return self in {Verdict.NOT_SUPPORTED, Verdict.INCONCLUSIVE}


@dataclass(frozen=True)
class EvidenceResult:
    """The outcome of running one piece of evidence."""

    verdict: Verdict
    detail: str
    measurements: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def supported(cls, detail: str, **measurements: Any) -> EvidenceResult:
        return cls(Verdict.SUPPORTED, detail, measurements)

    @classmethod
    def failed(cls, detail: str, **measurements: Any) -> EvidenceResult:
        return cls(Verdict.NOT_SUPPORTED, detail, measurements)

    @classmethod
    def inconclusive(cls, detail: str, **measurements: Any) -> EvidenceResult:
        return cls(Verdict.INCONCLUSIVE, detail, measurements)

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "detail": self.detail, "measurements": self.measurements}


@dataclass(frozen=True)
class Evidence:
    """A GSN Solution: something checkable, plus how to check it."""

    id: str
    description: str
    kind: str
    run: Callable[[], EvidenceResult]
    owner: str = "this software"

    def execute(self) -> EvidenceResult:
        """Run the check. A raising check is inconclusive, never passing --
        an assessor should see a broken check as an unmet claim, and a
        crash must never be mistaken for either success or a clean failure."""
        try:
            return self.run()
        except Exception as exc:  # noqa: BLE001 - see docstring
            return EvidenceResult.inconclusive(f"Evidence check raised {exc.__class__.__name__}: {str(exc)[:160]}")


@dataclass(frozen=True)
class Claim:
    """A GSN Goal, with its strategy, context, and children."""

    id: str
    statement: str
    strategy: str = ""
    context: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    sub_claims: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    undeveloped: bool = False
    delegated_to: str | None = None
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClaimOutcome:
    claim: Claim
    verdict: Verdict
    detail: str
    evidence: list[tuple[str, EvidenceResult]] = field(default_factory=list)
    depth: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.claim.id,
            "statement": self.claim.statement,
            "verdict": self.verdict.value,
            "detail": self.detail,
            "delegated_to": self.claim.delegated_to,
            "depth": self.depth,
            "evidence": [{"id": evidence_id, **result.to_dict()} for evidence_id, result in self.evidence],
        }


@dataclass
class SafetyCaseReport:
    """The executed case. Deliberately blunt about what it does not show."""

    title: str
    generated_at: str
    outcomes: list[ClaimOutcome]
    root: str

    @property
    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {verdict.value: 0 for verdict in Verdict}
        for outcome in self.outcomes:
            tally[outcome.verdict.value] += 1
        return tally

    @property
    def failures(self) -> list[ClaimOutcome]:
        return [outcome for outcome in self.outcomes if outcome.verdict.is_failure]

    @property
    def delegated(self) -> list[ClaimOutcome]:
        return [outcome for outcome in self.outcomes if outcome.verdict is Verdict.DELEGATED]

    @property
    def undeveloped(self) -> list[ClaimOutcome]:
        return [outcome for outcome in self.outcomes if outcome.verdict is Verdict.UNDEVELOPED]

    @property
    def root_verdict(self) -> Verdict:
        for outcome in self.outcomes:
            if outcome.claim.id == self.root:
                return outcome.verdict
        return Verdict.INCONCLUSIVE

    @property
    def certifiable(self) -> bool:
        """Always False, by construction.

        Certification is a judgement made by an accredited assessor about a
        specific machine in a specific installation. No amount of passing
        evidence in a repository produces it, so this property does not
        compute anything -- it exists to be quoted in reports that would
        otherwise be read as a certificate.
        """
        return False

    @property
    def verdict(self) -> str:
        if self.failures:
            return f"argument incomplete: {len(self.failures)} claim(s) not supported"
        if self.undeveloped:
            return f"argument partial: {len(self.undeveloped)} claim(s) undeveloped, {len(self.delegated)} delegated to certified equipment"
        return f"argued, not independently assessed: {len(self.delegated)} claim(s) delegated to certified equipment"

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "root": self.root,
            "verdict": self.verdict,
            "certifiable": self.certifiable,
            "certification_note": CERTIFICATION_NOTE,
            "counts": self.counts,
            "claims": [outcome.to_dict() for outcome in self.outcomes],
        }

    def render_text(self) -> str:
        symbols = {
            Verdict.SUPPORTED: "[ok]",
            Verdict.NOT_SUPPORTED: "[FAIL]",
            Verdict.INCONCLUSIVE: "[????]",
            Verdict.DELEGATED: "[dlg]",
            Verdict.UNDEVELOPED: "[----]",
            Verdict.NOT_APPLICABLE: "[n/a]",
        }
        lines = [self.title, "=" * len(self.title), f"generated {self.generated_at}", ""]
        for outcome in self.outcomes:
            indent = "  " * outcome.depth
            lines.append(f"{symbols[outcome.verdict]} {indent}{outcome.claim.id}: {outcome.claim.statement}")
            if outcome.detail:
                lines.append(f"       {indent}{outcome.detail}")
            for evidence_id, result in outcome.evidence:
                lines.append(f"       {indent}- {evidence_id}: {result.detail}")
        counts = self.counts
        lines += [
            "",
            f"supported {counts['supported']}  delegated {counts['delegated']}  undeveloped {counts['undeveloped']}  "
            f"not supported {counts['not_supported']}  inconclusive {counts['inconclusive']}",
            f"VERDICT: {self.verdict}",
            "",
            CERTIFICATION_NOTE,
        ]
        return "\n".join(lines)


CERTIFICATION_NOTE = (
    "This report is a self-assessment produced by the system about itself. It is not a certificate, "
    "not an independent assessment, and not evidence of conformity to ISO 13849, IEC 61508, IEC 62061, "
    "ISO 3691-4, or ANSI/RIA R15.08. Claims marked 'delegated' are discharged by certified equipment "
    "outside this software and by that equipment's own assessment, not by anything here."
)


class SafetyCase:
    """A claim tree plus its evidence, executable end to end."""

    def __init__(self, title: str, root: str) -> None:
        self.title = title
        self.root = root
        self._claims: dict[str, Claim] = {}
        self._evidence: dict[str, Evidence] = {}

    def claim(self, claim: Claim) -> Claim:
        self._claims[claim.id] = claim
        return claim

    def add_evidence(self, evidence: Evidence) -> Evidence:
        self._evidence[evidence.id] = evidence
        return evidence

    def evidence_for(self, evidence_id: str) -> Evidence | None:
        return self._evidence.get(evidence_id)

    def validate(self) -> list[str]:
        """Structural problems in the argument itself, found without running
        anything: dangling references, an absent root, or a cycle. A case
        that does not hold together cannot be evaluated, and saying so is
        more useful than a tree of inconclusive leaves."""
        problems: list[str] = []
        if self.root not in self._claims:
            problems.append(f"Root claim {self.root!r} is not defined.")
        for claim in self._claims.values():
            for child in claim.sub_claims:
                if child not in self._claims:
                    problems.append(f"Claim {claim.id!r} references undefined sub-claim {child!r}.")
            for evidence_id in claim.evidence:
                if evidence_id not in self._evidence:
                    problems.append(f"Claim {claim.id!r} references undefined evidence {evidence_id!r}.")
        problems.extend(self._find_cycles())
        return problems

    def _find_cycles(self) -> list[str]:
        visiting: set[str] = set()
        done: set[str] = set()
        problems: list[str] = []

        def walk(node: str, trail: tuple[str, ...]) -> None:
            if node in visiting:
                problems.append("Claim cycle: " + " -> ".join([*trail, node]))
                return
            if node in done or node not in self._claims:
                return
            visiting.add(node)
            for child in self._claims[node].sub_claims:
                walk(child, (*trail, node))
            visiting.discard(node)
            done.add(node)

        for claim_id in self._claims:
            walk(claim_id, ())
        return problems

    def verify(self) -> SafetyCaseReport:
        """Execute every reachable piece of evidence and roll the verdicts up.

        Evidence is memoised per run: a check referenced by two claims runs
        once, so the report cannot contain two different answers to the same
        question.
        """
        problems = self.validate()
        if problems:
            root_claim = self._claims.get(self.root) or Claim(self.root, "Root claim is missing.")
            return SafetyCaseReport(
                title=self.title,
                generated_at=stamp(),
                root=self.root,
                outcomes=[ClaimOutcome(root_claim, Verdict.INCONCLUSIVE, "; ".join(problems[:5]))],
            )

        executed: dict[str, EvidenceResult] = {}
        outcomes: list[ClaimOutcome] = []
        seen: set[str] = set()

        def evaluate(claim_id: str, depth: int) -> Verdict:
            claim = self._claims[claim_id]
            results: list[tuple[str, EvidenceResult]] = []
            for evidence_id in claim.evidence:
                # NOT `setdefault`: its default argument is evaluated
                # eagerly, so the check would run on every lookup and the
                # memoisation would silently do nothing.
                if evidence_id not in executed:
                    executed[evidence_id] = self._evidence[evidence_id].execute()
                results.append((evidence_id, executed[evidence_id]))
            child_verdicts = [evaluate(child, depth + 1) for child in claim.sub_claims]

            if claim.delegated_to:
                verdict, detail = Verdict.DELEGATED, f"Discharged outside this software by: {claim.delegated_to}."
            elif claim.undeveloped:
                verdict, detail = Verdict.UNDEVELOPED, claim.rationale or "Deliberately not argued here."
            elif not results and not child_verdicts:
                verdict, detail = Verdict.UNDEVELOPED, "No evidence and no sub-claims."
            else:
                # Only NOT_SUPPORTED counts as failing here. An
                # INCONCLUSIVE result means the check could not be
                # evaluated, which is a different verdict handled below --
                # reporting it as "not supported" would tell an assessor the
                # claim was tested and refuted, when it was neither.
                failing = [f"{evidence_id}: {result.detail}" for evidence_id, result in results if result.verdict is Verdict.NOT_SUPPORTED]
                inconclusive_children = [verdict for verdict in child_verdicts if verdict is Verdict.INCONCLUSIVE]
                unsupported_children = [verdict for verdict in child_verdicts if verdict is Verdict.NOT_SUPPORTED]
                if failing or unsupported_children:
                    verdict = Verdict.NOT_SUPPORTED
                    detail = "; ".join(failing) if failing else f"{len(unsupported_children)} sub-claim(s) not supported."
                elif any(result.verdict is Verdict.INCONCLUSIVE for _, result in results) or inconclusive_children:
                    verdict, detail = Verdict.INCONCLUSIVE, "Evidence could not be evaluated."
                else:
                    undeveloped_children = sum(1 for verdict in child_verdicts if verdict is Verdict.UNDEVELOPED)
                    delegated_children = sum(1 for verdict in child_verdicts if verdict is Verdict.DELEGATED)
                    verdict = Verdict.SUPPORTED
                    parts = [f"{len(results)} evidence item(s) passed"] if results else []
                    if delegated_children:
                        parts.append(f"{delegated_children} sub-claim(s) delegated")
                    if undeveloped_children:
                        parts.append(f"{undeveloped_children} sub-claim(s) undeveloped")
                    detail = "; ".join(parts) or "Supported."

            # A claim reachable from two parents is reported once, at the
            # depth it was first reached, so the printed tree stays readable.
            if claim_id not in seen:
                seen.add(claim_id)
                outcomes.append(ClaimOutcome(claim, verdict, detail, results, depth))
            return verdict

        evaluate(self.root, 0)
        return SafetyCaseReport(title=self.title, generated_at=stamp(), outcomes=outcomes, root=self.root)

    def to_json(self) -> str:
        """The argument itself (not a run of it), for review or diffing."""
        return json.dumps(
            {
                "title": self.title,
                "root": self.root,
                "claims": [claim.to_dict() for claim in self._claims.values()],
                "evidence": [{"id": item.id, "description": item.description, "kind": item.kind, "owner": item.owner} for item in self._evidence.values()],
            },
            indent=2,
            sort_keys=True,
        )


def all_claims(case: SafetyCase, claim_ids: Iterable[str]) -> tuple[str, ...]:
    """Small helper for building a case: assert the ids exist as you go."""
    resolved = tuple(claim_ids)
    missing = [claim_id for claim_id in resolved if claim_id not in case._claims]  # noqa: SLF001 - builder helper
    if missing:
        raise KeyError(f"Unknown claim ids: {missing}")
    return resolved
