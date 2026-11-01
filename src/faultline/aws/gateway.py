"""Small DynamoDB transport boundary with conditional, strongly consistent operations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol


class ConflictError(RuntimeError):
    """A conditional write lost a race and should be recomputed."""


@dataclass(frozen=True, slots=True)
class Put:
    table: str
    item: dict[str, Any]
    expected_revision: int | None = None


class Gateway(Protocol):
    def get(self, table: str, pk: str, sk: str) -> dict[str, Any] | None: ...

    def put_if_absent(self, table: str, item: dict[str, Any]) -> bool: ...

    def query_range(
        self, table: str, pk: str, start: str, end: str, limit: int
    ) -> list[dict[str, Any]]: ...

    def query_account(self, table: str, account_id: str, limit: int) -> list[dict[str, Any]]: ...

    def transact(self, puts: list[Put]) -> None: ...


def _code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            return error.get("Code")
    return None


class Boto3Gateway:
    """Low-level DynamoDB client adapter. boto3 is imported only in the cloud runtime."""

    def __init__(self, client: Any) -> None:
        from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

        self.client = client
        self.serializer = TypeSerializer()
        self.deserializer = TypeDeserializer()

    def _item(self, value: dict[str, Any]) -> dict[str, Any]:
        return {key: self.serializer.serialize(item) for key, item in value.items()}

    def _plain(self, value: dict[str, Any]) -> dict[str, Any]:
        return {key: self.deserializer.deserialize(item) for key, item in value.items()}

    def get(self, table: str, pk: str, sk: str) -> dict[str, Any] | None:
        response = self.client.get_item(
            TableName=table, Key=self._item({"pk": pk, "sk": sk}), ConsistentRead=True
        )
        item = response.get("Item")
        return self._plain(item) if item else None

    def put_if_absent(self, table: str, item: dict[str, Any]) -> bool:
        try:
            self.client.put_item(
                TableName=table, Item=self._item(item),
                ConditionExpression="attribute_not_exists(pk)",
            )
            return True
        except Exception as exc:
            if _code(exc) == "ConditionalCheckFailedException":
                return False
            raise

    def query_range(
        self, table: str, pk: str, start: str, end: str, limit: int
    ) -> list[dict[str, Any]]:
        response = self.client.query(
            TableName=table,
            KeyConditionExpression="#pk = :pk AND #sk BETWEEN :start AND :end",
            ExpressionAttributeNames={"#pk": "pk", "#sk": "sk"},
            ExpressionAttributeValues={
                ":pk": self.serializer.serialize(pk),
                ":start": self.serializer.serialize(start),
                ":end": self.serializer.serialize(end),
            },
            ConsistentRead=True, Limit=limit,
        )
        return [self._plain(item) for item in response.get("Items", [])]

    def query_account(self, table: str, account_id: str, limit: int) -> list[dict[str, Any]]:
        response = self.client.query(
            TableName=table, IndexName="AccountTime",
            KeyConditionExpression="#gpk = :account",
            ExpressionAttributeNames={"#gpk": "gsi1pk"},
            ExpressionAttributeValues={
                ":account": self.serializer.serialize(f"ACCOUNT#{account_id}")
            },
            ScanIndexForward=False, Limit=limit,
        )
        return [self._plain(item) for item in response.get("Items", [])]

    def transact(self, puts: list[Put]) -> None:
        if not 1 <= len(puts) <= 100:
            raise ValueError("DynamoDB transaction must contain 1-100 actions")
        keys = [(put.table, put.item["pk"], put.item["sk"]) for put in puts]
        if len(set(keys)) != len(keys):
            raise ValueError("DynamoDB transaction targets the same item twice")
        actions = []
        for put in puts:
            operation: dict[str, Any] = {
                "TableName": put.table, "Item": self._item(put.item),
                "ConditionExpression": (
                    "attribute_not_exists(pk)" if put.expected_revision is None
                    else "revision = :expected"
                ),
            }
            if put.expected_revision is not None:
                operation["ExpressionAttributeValues"] = {
                    ":expected": self.serializer.serialize(put.expected_revision)
                }
            actions.append({"Put": operation})
        token_source = json.dumps(
            [(put.table, put.item, put.expected_revision) for put in puts],
            sort_keys=True, default=str, separators=(",", ":"),
        )
        token = hashlib.sha256(token_source.encode()).hexdigest()[:32]
        try:
            self.client.transact_write_items(TransactItems=actions, ClientRequestToken=token)
        except Exception as exc:
            code = _code(exc)
            if code == "TransactionCanceledException":
                reasons = getattr(exc, "response", {}).get("CancellationReasons", [])
                if reasons and all(
                    reason.get("Code") in ("None", "ConditionalCheckFailed", "TransactionConflict")
                    for reason in reasons
                ):
                    raise ConflictError("conditional transaction conflict") from exc
            if code in ("ConditionalCheckFailedException", "TransactionConflictException"):
                raise ConflictError("conditional transaction conflict") from exc
            raise
