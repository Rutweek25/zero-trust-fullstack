from __future__ import annotations

import secrets
from datetime import datetime, timezone
from agent.time_utils import now_ist

import requests

from agent.config import AgentConfig
from agent.core.retry import ExponentialBackoff
from agent.security.signing import sign_payload


class AgentApiClient:
    def __init__(self, config: AgentConfig, logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()

    def _post_with_fallback(
        self,
        paths: list[str],
        payload: dict,
        headers: dict | None = None,
        backoff: ExponentialBackoff | None = None,
    ):
        if backoff is None:
            backoff = ExponentialBackoff(base_delay=1.0, max_delay=self.config.max_backoff_seconds)

        retryable_codes = {408, 429, 500, 502, 503, 504}
        attempt = 0

        while True:
            for path in paths:
                url = f"{self.config.server_url}{path}"
                try:
                    response = self.session.post(
                        url,
                        json=payload,
                        headers=headers or {},
                        timeout=self.config.request_timeout,
                    )

                    if response.status_code == 404 and len(paths) > 1:
                        self.logger.warning("endpoint not found status=404 path=%s trying fallback", path)
                        continue

                    if response.status_code in retryable_codes:
                        self.logger.warning("retryable response status=%s path=%s", response.status_code, path)
                        continue

                    return response
                except requests.RequestException as exc:
                    self.logger.warning("network error path=%s error=%s", path, str(exc))

            delay = backoff.next_delay()
            attempt += 1
            self.logger.warning("all endpoints failed attempt=%s backoff=%.2fs", attempt, delay)
            if delay > 0:
                import time

                time.sleep(delay)

    def register(self, device_uuid: str, registration_info: dict) -> dict:
        payload = {
            "device_uuid": device_uuid,
            "hostname": registration_info["hostname"],
            "os_version": registration_info["os_version"],
            "system_info": registration_info.get("system_info") or {},
        }
        response = self._post_with_fallback(self.config.register_paths, payload)
        response.raise_for_status()
        return response.json()

    def send_heartbeat(self, token: str, payload: dict, signing_key: str) -> dict:
        signature = sign_payload(payload, signing_key)
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Agent-Signature": signature,
            "X-Agent-Signature-Alg": "HMAC-SHA256",
        }
        response = self._post_with_fallback(self.config.heartbeat_paths, payload, headers=headers)
        response.raise_for_status()
        return response.json()

    def rotate_token(self, device_uuid: str, token: str) -> str | None:
        payload = {
            "device_uuid": device_uuid,
            "current_token": token,
            "timestamp": now_ist().isoformat(),
            "nonce": secrets.token_hex(16),
        }

        try:
            response = self._post_with_fallback(self.config.rotate_paths, payload)
            if response.status_code == 404:
                self.logger.warning("rotation endpoint not available, fallback to re-register")
                return None

            response.raise_for_status()
            data = response.json()
            return data.get("new_token") or data.get("agent_token")
        except Exception as exc:
            self.logger.error("token rotation failed error=%s", str(exc))
            return None
