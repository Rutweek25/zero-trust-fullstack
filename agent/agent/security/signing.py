import hashlib
import hmac
import json


def canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: dict, signing_key: str) -> str:
    body = canonical_payload(payload)
    signature = hmac.new(signing_key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return signature
