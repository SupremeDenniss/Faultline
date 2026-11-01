"""Pure, deterministic detection rules for observed API activity."""

from __future__ import annotations

from typing import Protocol

from faultline.models import Detection, Event

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


class Rule(Protocol):
    rule_id: str

    def match(self, event: Event) -> Detection | None: ...


class AttachAdministratorPolicy:
    rule_id = "FLT-IAM-001"

    def match(self, event: Event) -> Detection | None:
        if (
            event.event_source != "iam.amazonaws.com"
            or event.event_name != "AttachRolePolicy"
            or event.error_code is not None
            or event.request.get("policyArn") != ADMIN_POLICY_ARN
            or not event.request.get("roleName")
        ):
            return None
        role = event.request["roleName"]
        return Detection(
            rule_id=self.rule_id,
            severity="high",
            title="AdministratorAccess policy attached to role",
            explanation=(
                "An AttachRolePolicy API event applied the AWS-managed AdministratorAccess "
                "policy to a role. This activity may be authorized; investigate its context."
            ),
            resource=role,
            event_reference=event.identity,
            evidence={"roleName": role, "policyArn": ADMIN_POLICY_ARN},
        )


class StopCloudTrailLogging:
    rule_id = "FLT-CT-001"

    def match(self, event: Event) -> Detection | None:
        if (
            event.event_source != "cloudtrail.amazonaws.com"
            or event.event_name != "StopLogging"
            or event.error_code is not None
        ):
            return None
        trail = event.request.get("name") or next(iter(event.resources), None)
        if trail is None:
            return None
        return Detection(
            rule_id=self.rule_id,
            severity="high",
            title="CloudTrail logging stopped",
            explanation=(
                "A StopLogging API event targeted a CloudTrail trail. This activity may be "
                "authorized; investigate its context."
            ),
            resource=trail,
            event_reference=event.identity,
            evidence={"trail": trail},
        )


RULES: tuple[Rule, ...] = (AttachAdministratorPolicy(), StopCloudTrailLogging())


def detect(event: Event, rules: tuple[Rule, ...] = RULES) -> tuple[Detection, ...]:
    return tuple(detection for rule in rules if (detection := rule.match(event)) is not None)
