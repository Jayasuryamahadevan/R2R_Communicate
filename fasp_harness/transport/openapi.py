"""Public OpenAPI description of the stable HTTP ingress and operator routes."""

from __future__ import annotations

from typing import Any


def schema() -> dict[str, Any]:
    def ref(name: str) -> dict[str, str]:
        return {"$ref": f"#/components/schemas/{name}"}

    ok = {"description": "Request accepted", "content": {"application/json": {"schema": {"type": "object"}}}}
    error = {"description": "FASP protocol error", "content": {"application/json": {"schema": ref("ProtocolError")}}}

    def post(summary: str, request_schema: dict[str, Any], *, admin: bool = False) -> dict[str, Any]:
        operation: dict[str, Any] = {
            "summary": summary,
            "requestBody": {"required": True, "content": {"application/json": {"schema": request_schema}}},
            "responses": {"200": ok, "400": error, "401": error, "413": error},
        }
        if admin:
            operation["security"] = [{"AdminToken": []}]
        return {"post": operation}

    def get(summary: str, *, admin: bool = False, response_schema: dict[str, Any] | None = None) -> dict[str, Any]:
        operation: dict[str, Any] = {
            "summary": summary,
            "responses": {"200": {"description": "Response", "content": {"application/json": {"schema": response_schema or {"type": "object"}}}}, "401": error},
        }
        if admin:
            operation["security"] = [{"AdminToken": []}]
        return {"get": operation}

    return {
        "openapi": "3.1.0",
        "info": {
            "title": "FASP Harness HTTP API",
            "version": "1.0.0",
            "description": "Signed FASP envelopes are the authorization boundary. Use HTTPS on Wi-Fi and Ethernet. Bluetooth uses the same envelope format over a separate bounded bearer.",
        },
        "servers": [{"url": "/"}],
        "paths": {
            "/profile": get("Get this node's signed ID card", response_schema=ref("IdCard")),
            "/.well-known/fasp/id-card.json": get("Get this node's signed ID card", response_schema=ref("IdCard")),
            "/livez": get("Process liveness"),
            "/readyz": get("Node readiness"),
            "/health": get("Minimal public health"),
            "/health/detail": get("Detailed node health", admin=True),
            "/safety": get("Safety observation status", admin=True),
            "/fleet": get("Fleet state", admin=True),
            "/peers": get("Paired and pending peer records", admin=True),
            "/metrics": {"get": {"summary": "Prometheus metrics", "security": [{"AdminToken": []}], "responses": {"200": {"description": "Prometheus text exposition", "content": {"text/plain": {"schema": {"type": "string"}}}}, "401": error}}},
            "/pair/hello": post("Request pending pairing with a signed ID card", {"type": "object", "required": ["id_card"], "properties": {"id_card": ref("IdCard")}}),
            "/pair/confirm": post("Confirm a pending peer after comparing pairing codes", {"type": "object", "required": ["peer_id", "pair_code"], "properties": {"peer_id": {"type": "string"}, "pair_code": {"type": "string"}, "allowed_capability_prefixes": {"type": "array", "items": {"type": "string"}}}}, admin=True),
            "/pair/revoke": post("Revoke a peer", {"type": "object", "required": ["peer_id"], "properties": {"peer_id": {"type": "string"}, "reason": {"type": "string"}, "revocation_ref": {"type": "string"}}}, admin=True),
            "/grants/issue": post("Issue a scoped grant", {"type": "object", "required": ["subject_peer", "capability_prefixes"], "properties": {"subject_peer": {"type": "string"}, "capability_prefixes": {"type": "array", "items": {"type": "string"}}, "duration_seconds": {"type": "integer", "minimum": 1}, "purpose": {"type": "string"}, "constraints": {"type": "object"}}}, admin=True),
            "/grants/revoke": post("Revoke a grant", {"type": "object", "required": ["grant_id"], "properties": {"grant_id": {"type": "string"}}}, admin=True),
            "/fasp/v1/envelopes": post("Submit a signed FASP envelope", ref("Envelope")),
            "/fasp/v1/receipts": post("Submit a signed receipt.processed envelope", ref("Envelope")),
        },
        "components": {
            "securitySchemes": {"AdminToken": {"type": "apiKey", "in": "header", "name": "X-FASP-Admin-Token", "description": "Read from the node's private state/admin_token file. Never place it in a URL."}},
            "schemas": {
                "IdCard": {
                    "type": "object", "required": ["fasp", "type", "system_id", "public_key", "endpoints", "expires_at", "signature"],
                    "properties": {"fasp": {"type": "string"}, "type": {"const": "id_card"}, "system_id": {"type": "string"}, "display_name": {"type": "string"}, "public_key": {"type": "string"}, "endpoints": {"type": "object", "additionalProperties": {"type": "string"}}, "expires_at": {"type": "string", "format": "date-time"}, "signature": {"type": "object"}},
                    "additionalProperties": True,
                },
                "Envelope": {
                    "type": "object", "required": ["fasp", "kind", "message_id", "from", "to", "issued_at", "expires_at", "nonce", "payload", "signature"],
                    "properties": {"fasp": {"type": "string"}, "kind": {"type": "string"}, "message_id": {"type": "string", "format": "uuid"}, "conversation_id": {"type": "string", "format": "uuid"}, "causation_id": {"type": ["string", "null"]}, "from": {"type": "string"}, "to": {"type": "string"}, "issued_at": {"type": "string", "format": "date-time"}, "expires_at": {"type": "string", "format": "date-time"}, "nonce": {"type": "string"}, "payload": {"type": "object"}, "signature": {"type": "object"}},
                    "additionalProperties": True,
                    "description": "Ed25519 signature over RFC 8785 canonical JSON; the sender must already be paired and authorized for the requested capability.",
                },
                "ProtocolError": {"type": "object", "required": ["fasp", "type", "error"], "properties": {"fasp": {"type": "string"}, "type": {"const": "protocol.error"}, "error": {"type": "object", "required": ["code", "detail"], "properties": {"code": {"type": "string"}, "detail": {"type": "string"}}}}},
            },
        },
    }
