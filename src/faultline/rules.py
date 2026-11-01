"""Pure, deterministic detection rules for observed API activity."""

from __future__ import annotations

from typing import Protocol

from faultline.models import Detection, Event

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


class Rule(Protocol):
    rule_id: str
    version: str

    def match(self, event: Event) -> Detection | None: ...


class AttachAdministratorPolicy:
    rule_id = "FLT-IAM-001"
    version = "1.0.0"

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
            rule_version=self.version,
            severity="high",
            title="AdministratorAccess attachment API activity",
            explanation=(
                "An AttachRolePolicy API event targeted a role with the AWS-managed "
                "AdministratorAccess policy and was not reported as failed. This activity "
                "may be authorized; verify current permissions and investigate its context."
            ),
            resource=role,
            event_reference=event.identity,
            evidence={"roleName": role, "policyArn": ADMIN_POLICY_ARN},
        )


class StopCloudTrailLogging:
    rule_id = "FLT-CT-001"
    version = "1.0.0"

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
            rule_version=self.version,
            severity="high",
            title="CloudTrail StopLogging API activity",
            explanation=(
                "A StopLogging API event targeted a CloudTrail trail and was not reported "
                "as failed. This activity may be authorized; verify trail state separately."
            ),
            resource=trail,
            event_reference=event.identity,
            evidence={"trail": trail},
        )


class AssumeRole:
    rule_id = "FLT-STS-001"
    version = "1.0.0"

    def match(self, event: Event) -> Detection | None:
        if (
            event.event_source != "sts.amazonaws.com"
            or event.event_name != "AssumeRole"
            or event.error_code is not None
            or not event.request.get("roleArn")
        ):
            return None
        role_arn = event.request["roleArn"]
        return Detection(
            rule_id=self.rule_id,
            rule_version=self.version,
            severity="medium",
            title="Role assumption requested",
            explanation=(
                "An AssumeRole API event targeted a role and was not reported as failed. "
                "The event alone does not establish misuse or subsequent actions."
            ),
            resource=role_arn,
            event_reference=event.identity,
            evidence={"roleArn": role_arn},
        )


class DeleteCloudTrailTrail:
    rule_id = "FLT-CT-002"
    version = "1.0.0"

    def match(self, event: Event) -> Detection | None:
        if (
            event.event_source != "cloudtrail.amazonaws.com"
            or event.event_name != "DeleteTrail"
            or event.error_code is not None
        ):
            return None
        trail = event.request.get("name") or next(iter(event.resources), None)
        if trail is None:
            return None
        return Detection(
            rule_id=self.rule_id,
            rule_version=self.version,
            severity="high",
            title="CloudTrail DeleteTrail API activity",
            explanation=(
                "A DeleteTrail API event targeted a CloudTrail trail and was not reported as "
                "failed. Investigate authorization and verify trail state separately."
            ),
            resource=trail,
            event_reference=event.identity,
            evidence={"trail": trail},
        )


RULES: tuple[Rule, ...] = (
    AttachAdministratorPolicy(), StopCloudTrailLogging(), AssumeRole(), DeleteCloudTrailTrail()
)


def detect(event: Event, rules: tuple[Rule, ...] = RULES) -> tuple[Detection, ...]:
    return tuple(detection for rule in rules if (detection := rule.match(event)) is not None)
