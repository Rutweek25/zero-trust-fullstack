"""
Microsoft OAuth utilities for Zero Trust system.
Handles Microsoft ID token validation and user creation/login.
"""

from datetime import datetime, timezone
from time_utils import now_ist
from pathlib import Path
import os
import time
import logging

import requests
from dotenv import load_dotenv, find_dotenv
from jose import jwt, JWTError
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

import models

env_path = Path(__file__).parent / ".env"


def _load_env() -> list[str]:
    candidates = [env_path]
    found_env = find_dotenv(".env", usecwd=True)
    if found_env:
        candidates.append(Path(found_env))

    loaded_paths = []
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            load_dotenv(dotenv_path=candidate, override=True)
            loaded_paths.append(str(candidate))
    return loaded_paths


_ENV_PATHS = _load_env()

logger = logging.getLogger("microsoft_oauth")
logger.info("Microsoft OAuth module loaded from %s", __file__)

_OPENID_CONFIG_CACHE: dict[str, dict] = {}
_JWKS_CACHE: dict[str, dict] = {}
_CACHE_TTL_SECONDS = 3600


def _load_env_vars() -> tuple[str | None, str, list[str]]:
    loaded_paths = _load_env()
    client_id = os.getenv("MICROSOFT_CLIENT_ID")
    tenant_id = os.getenv("MICROSOFT_TENANT_ID", "common")
    logger.debug(
        "Loaded Microsoft env vars client_id=%s tenant_id=%s paths=%s",
        bool(client_id),
        tenant_id,
        loaded_paths or _ENV_PATHS
    )
    return client_id, tenant_id, (loaded_paths or _ENV_PATHS)


def _fetch_json(url: str) -> dict:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.json()


def _get_openid_config(tenant_id: str) -> dict:
    now = time.time()
    cached = _OPENID_CONFIG_CACHE.get(tenant_id)
    if cached and cached["expires_at"] > now:
        return cached["data"]

    config_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    data = _fetch_json(config_url)
    _OPENID_CONFIG_CACHE[tenant_id] = {"data": data, "expires_at": now + _CACHE_TTL_SECONDS}
    return data


def _get_jwks(tenant_id: str) -> list:
    now = time.time()
    cached = _JWKS_CACHE.get(tenant_id)
    if cached and cached["expires_at"] > now:
        return cached["data"]

    openid_config = _get_openid_config(tenant_id)
    jwks_uri = openid_config.get("jwks_uri")
    if not jwks_uri:
        raise ValueError("Microsoft OpenID config missing jwks_uri")

    jwks = _fetch_json(jwks_uri)
    keys = jwks.get("keys", [])
    if not keys:
        raise ValueError("Microsoft JWKS returned no keys")

    _JWKS_CACHE[tenant_id] = {"data": keys, "expires_at": now + _CACHE_TTL_SECONDS}
    return keys


def _get_token_signing_key(token: str, tenant_id: str) -> dict:
    header = jwt.get_unverified_header(token)
    key_id = header.get("kid")
    if not key_id:
        raise ValueError("Microsoft token missing key ID")

    keys = _get_jwks(tenant_id)
    key = next((candidate for candidate in keys if candidate.get("kid") == key_id), None)
    if key:
        return key

    _JWKS_CACHE.pop(tenant_id, None)
    keys = _get_jwks(tenant_id)
    key = next((candidate for candidate in keys if candidate.get("kid") == key_id), None)
    if key:
        return key

    raise ValueError("Unable to find signing key for Microsoft token")


def _get_expected_issuer(tenant_id: str) -> str:
    openid_config = _get_openid_config(tenant_id)
    issuer = openid_config.get("issuer")
    if not issuer:
        raise ValueError("Microsoft OpenID config missing issuer")
    return issuer.rstrip("/")


async def verify_microsoft_token(token: str) -> dict:
    microsoft_client_id, microsoft_tenant_id, env_paths = _load_env_vars()

    if not microsoft_client_id:
        paths_info = ", ".join(env_paths) if env_paths else "(no .env found)"
        raise ValueError(
            "MICROSOFT_CLIENT_ID not configured. "
            f"Checked: {paths_info}. Module: {__file__}"
        )

    if not token or not token.strip():
        raise ValueError("Microsoft id_token is empty or missing")

    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_claims = jwt.get_unverified_claims(token)
    except Exception as exc:
        raise ValueError(f"Unable to parse Microsoft token claims: {str(exc)}")

    token_tenant_id = unverified_claims.get("tid")
    if microsoft_tenant_id and microsoft_tenant_id != "common":
        if token_tenant_id and token_tenant_id != microsoft_tenant_id:
            raise ValueError(
                f"Token tenant mismatch. Got: {token_tenant_id}, Expected: {microsoft_tenant_id}"
            )

    effective_tenant_id = microsoft_tenant_id or token_tenant_id or "common"
    expected_issuer = _get_expected_issuer(effective_tenant_id)
    kid = unverified_header.get("kid")
    logger.debug(
        "Microsoft token header kid=%s tid=%s expected_issuer=%s",
        kid,
        token_tenant_id,
        expected_issuer,
    )

    signing_key = _get_token_signing_key(token, effective_tenant_id)

    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=microsoft_client_id,
            issuer=expected_issuer,
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_at_hash": False,
            },
        )
    except JWTError as exc:
        logger.debug("Microsoft token validation failed: %s", str(exc))
        raise ValueError(f"Microsoft token verification failed: {str(exc)}")

    issuer = payload.get("iss")
    logger.info("Microsoft token validated iss=%s aud=%s", issuer, payload.get("aud"))

    email = (
        payload.get("preferred_username")
        or payload.get("email")
        or payload.get("upn")
        or payload.get("unique_name")
    )
    if not email:
        oid_or_sub = payload.get("oid") or payload.get("sub")
        tid = payload.get("tid") or effective_tenant_id
        if oid_or_sub and tid:
            email = f"{oid_or_sub}@{tid}.microsoft"
        else:
            raise ValueError("Microsoft token missing email claim")

    subject = payload.get("sub") or payload.get("oid")
    if not subject:
        raise ValueError("Microsoft token missing subject claim")

    return {
        "email": email,
        "name": payload.get("name", email.split("@")[0]),
        "sub": subject,
        "issuer": issuer,
    }


def get_or_create_microsoft_user(user_info: dict, db: Session):
    email = (user_info.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("Invalid Microsoft user email")

    subject = user_info.get("sub")
    if not subject:
        raise ValueError("Missing Microsoft user subject")

    try:
        user_by_microsoft_id = db.query(models.User).filter(models.User.microsoft_id == subject).first()
        if user_by_microsoft_id:
            linked_email = user_by_microsoft_id.personal_email or user_by_microsoft_id.company_email
            if linked_email and linked_email.lower() != email:
                raise ValueError("Microsoft account is already linked to another email")

            if not user_by_microsoft_id.personal_email and not user_by_microsoft_id.company_email:
                user_by_microsoft_id.personal_email = email
            if not user_by_microsoft_id.auth_provider:
                user_by_microsoft_id.auth_provider = "microsoft"
            return user_by_microsoft_id

        existing_user = db.query(models.User).filter(
            or_(
                models.User.personal_email == email,
                models.User.company_email == email,
            )
        ).first()

        if existing_user:
            if existing_user.microsoft_id and existing_user.microsoft_id != subject:
                raise ValueError("Email already linked to a different Microsoft account")

            existing_user.microsoft_id = subject
            if not existing_user.auth_provider:
                existing_user.auth_provider = "local"
            if not existing_user.personal_email and not existing_user.company_email:
                existing_user.personal_email = email
            return existing_user

        email_prefix = email.split("@")[0]
        base_username = email_prefix
        username = base_username
        counter = 1

        while db.query(models.User).filter(models.User.username == username).first():
            username = f"{base_username}{counter}"
            counter += 1

        new_user = models.User(
            username=username,
            name=user_info.get("name", email_prefix),
            company_email=email,
            personal_email=email,
            password_hash="",
            auth_provider="microsoft",
            microsoft_id=subject,
            role="user",
            status="active",
            created_at=now_ist()
        )

        db.add(new_user)
        db.flush()
        logger.info("Created new Microsoft OAuth user: username=%s email=%s", username, email)
        return new_user

    except IntegrityError as exc:
        db.rollback()
        logger.error("Microsoft user create conflict for email=%s sub=%s: %s", email, subject, str(exc))
        raise ValueError("Account conflict: email or Microsoft account already exists")
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Database error during Microsoft login for email=%s: %s", email, str(exc))
        raise ValueError("Database error while creating Microsoft account")

