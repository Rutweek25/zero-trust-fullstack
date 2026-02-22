from __future__ import annotations

import datetime
import secrets
import threading
import time
from pathlib import Path

from agent.collector.metrics import collect_metrics
from agent.collector.system_info import get_registration_info, get_system_info
from agent.collector.usb_monitor import monitor_usb
from agent.config import get_device_id, load_config
from agent.core.integrity import verify_or_init_integrity
from agent.core.logger import setup_logging
from agent.core.queue_store import LocalQueueStore
from agent.core.retry import ExponentialBackoff
from agent.network.client import AgentApiClient
from agent.security.token_store import SecureTokenStore
from agent.time_utils import now_ist


class AgentRuntime:
    def __init__(self):
        self.config = load_config()
        self.logger = setup_logging(self.config.log_file)
        self.client = AgentApiClient(self.config, self.logger)
        self.device_uuid = get_device_id()
        self.token_store = SecureTokenStore(self.config.token_file)
        self.queue = LocalQueueStore(self.config.queue_file, self.config.queue_max_items)
        self.stop_event = threading.Event()
        self.usb_thread = None
        self.agent_token = self.token_store.load()
        self.is_approved = True
        self.registration_backoff = ExponentialBackoff(base_delay=1, max_delay=self.config.max_backoff_seconds)
        self.send_backoff = ExponentialBackoff(base_delay=1, max_delay=self.config.max_backoff_seconds)

    def _integrity_files(self) -> list[str]:
        root = Path(__file__).resolve().parent
        return [
            str(root / "main.py"),
            str(root / "network" / "client.py"),
            str(root / "security" / "token_store.py"),
            str(root / "security" / "signing.py"),
        ]

    def verify_integrity(self) -> bool:
        valid, expected, current = verify_or_init_integrity(self.config.integrity_file, self._integrity_files())
        if valid and expected == "initialized":
            self.logger.warning("integrity baseline initialized")
            return True
        if valid:
            self.logger.info("integrity check passed")
            return True

        self.logger.error("integrity violation expected=%s current=%s", expected, current)
        return False

    def _enqueue_system_info_event(self) -> None:
        event = get_system_info()
        event["device_id"] = self.device_uuid
        event["kind"] = "system_info"
        self.queue.enqueue(event)

    def _enqueue_heartbeat(self) -> None:
        # Collect metrics asynchronously to avoid blocking main loop
        metrics = collect_metrics() if self.is_approved else {}
        payload = {
            "device_uuid": self.device_uuid,
            "timestamp": now_ist().isoformat(),
            "nonce": secrets.token_hex(16),
            "metrics": metrics,
            "kind": "heartbeat",
        }
        self.queue.enqueue(payload)

    def _on_usb_event(self, event_data: dict) -> None:
        event = {
            "device_uuid": self.device_uuid,
            "timestamp": now_ist().isoformat(),
            "nonce": secrets.token_hex(16),
            "metrics": {"usb_devices": [event_data]},
            "kind": "usb_event",
        }
        self.queue.enqueue(event)
        self.logger.info("usb event queued")
        # Flush USB events immediately without waiting for heartbeat interval
        self._flush_once()

    def _ensure_registered(self) -> bool:
        if self.agent_token:
            return True

        try:
            registration_data = get_registration_info()
            response = self.client.register(self.device_uuid, registration_data)
            token = response.get("agent_token")
            if not token:
                raise RuntimeError("registration response missing agent_token")

            if len(token) != 128:
                self.logger.warning("received non-128 token length=%s (backend contract mismatch)", len(token))

            self.agent_token = token
            self.token_store.save(token)
            self.is_approved = bool(response.get("is_approved", True))
            self.registration_backoff.reset()
            self.logger.info("agent registered approved=%s", self.is_approved)
            return True
        except Exception as exc:
            delay = self.registration_backoff.next_delay()
            self.logger.error("registration failed error=%s retry_in=%.2fs", str(exc), delay)
            time.sleep(delay)
            return False

    def _handle_rotation(self) -> None:
        if not self.agent_token:
            return

        new_token = self.client.rotate_token(self.device_uuid, self.agent_token)
        if new_token:
            self.agent_token = new_token
            self.token_store.save(new_token)
            self.logger.info("agent token rotated")
            return

        self.logger.warning("rotation unavailable or failed, forcing re-registration")
        self.token_store.clear()
        self.agent_token = None

    def _flush_usb_priority(self) -> None:
        """Flush only USB events first, then regular heartbeats."""
        if not self.agent_token:
            return
        
        # Flush all USB events first for immediate delivery
        while True:
            item = self.queue.peek()
            if not item or item.get("kind") != "usb_event":
                break
            self._flush_once()

    def _flush_once(self) -> bool:
        if not self.agent_token:
            return False

        item = self.queue.peek()
        if not item:
            return True

        payload = {
            "device_uuid": item.get("device_uuid", self.device_uuid),
            "metrics": item.get("metrics", {}),
            "timestamp": item.get("timestamp"),
            "nonce": item.get("nonce"),
        }

        signing_key = self.config.signing_key or self.agent_token

        try:
            response = self.client.send_heartbeat(self.agent_token, payload, signing_key)
            self.queue.pop()
            self.send_backoff.reset()

            self.is_approved = bool(response.get("is_approved", True))
            if response.get("requires_rotation"):
                self._handle_rotation()

            return True
        except Exception as exc:
            delay = self.send_backoff.next_delay()
            self.logger.warning("flush failed error=%s queue_size=%s retry_in=%.2fs", str(exc), self.queue.size(), delay)
            time.sleep(delay)
            return False

    def start(self) -> None:
        if not self.verify_integrity() and self.config.fail_on_tamper:
            raise RuntimeError("agent integrity check failed")

        self._enqueue_system_info_event()

        self.usb_thread = threading.Thread(target=monitor_usb, args=(self._on_usb_event, self.stop_event), daemon=True)
        self.usb_thread.start()
        self.logger.info("usb monitor started")

        while not self.stop_event.is_set():
            if not self._ensure_registered():
                continue

            # Flush USB events with priority
            self._flush_usb_priority()
            
            # Then enqueue and flush regular heartbeat
            self._enqueue_heartbeat()
            self._flush_once()

            interval = self.config.heartbeat_interval if self.is_approved else self.config.pending_interval
            self.stop_event.wait(interval)

    def stop(self) -> None:
        self.stop_event.set()
        self.logger.info("agent stopped")


def main() -> None:
    runtime = AgentRuntime()
    try:
        runtime.start()
    except KeyboardInterrupt:
        runtime.stop()
    except Exception:
        runtime.logger.exception("fatal runtime error")
        raise


if __name__ == "__main__":
    main()
