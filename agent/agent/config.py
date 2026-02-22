import os
import platform
import uuid
from dataclasses import dataclass


def get_base_dir() -> str:
    if platform.system() == "Windows":
        program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        base_dir = os.path.join(program_data, "CryptoAgent")
    else:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "runtime"))

    os.makedirs(base_dir, exist_ok=True)
    return base_dir


BASE_DIR = get_base_dir()
DEVICE_ID_FILE = os.path.join(BASE_DIR, "device_id.txt")


@dataclass
class AgentConfig:
    server_url: str
    register_paths: list[str]
    heartbeat_paths: list[str]
    rotate_paths: list[str]
    heartbeat_interval: int
    pending_interval: int
    request_timeout: float
    max_backoff_seconds: int
    queue_max_items: int
    token_file: str
    log_file: str
    queue_file: str
    integrity_file: str
    signing_key: str
    fail_on_tamper: bool


def load_config() -> AgentConfig:
    server_url = os.getenv("AGENT_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
    register_path = os.getenv("AGENT_REGISTER_PATH", "/agent/register")
    heartbeat_path = os.getenv("AGENT_HEARTBEAT_PATH", "/agent/heartbeat")
    rotate_path = os.getenv("AGENT_ROTATE_PATH", "/agent/token/rotate")

    register_paths = list(dict.fromkeys([register_path, "/agent/register", "/api/agent/register"]))
    heartbeat_paths = list(dict.fromkeys([heartbeat_path, "/agent/heartbeat", "/api/agent/heartbeat"]))
    rotate_paths = list(dict.fromkeys([rotate_path, "/agent/token/rotate", "/api/agent/token/rotate"]))

    return AgentConfig(
        server_url=server_url,
        register_paths=register_paths,
        heartbeat_paths=heartbeat_paths,
        rotate_paths=rotate_paths,
        heartbeat_interval=int(os.getenv("AGENT_HEARTBEAT_INTERVAL", "30")),
        pending_interval=int(os.getenv("AGENT_PENDING_HEARTBEAT_INTERVAL", "60")),
        request_timeout=float(os.getenv("AGENT_REQUEST_TIMEOUT", "8")),
        max_backoff_seconds=int(os.getenv("AGENT_MAX_BACKOFF_SECONDS", "120")),
        queue_max_items=int(os.getenv("AGENT_QUEUE_MAX_ITEMS", "1000")),
        token_file=os.path.join(BASE_DIR, "agent_token.json"),
        log_file=os.path.join(BASE_DIR, "agent.log"),
        queue_file=os.path.join(BASE_DIR, "pending_queue.json"),
        integrity_file=os.path.join(BASE_DIR, "integrity.sha256"),
        signing_key=os.getenv("AGENT_SIGNING_KEY", ""),
        fail_on_tamper=os.getenv("AGENT_FAIL_ON_TAMPER", "1") == "1",
    )


def get_device_id() -> str:
    if os.path.exists(DEVICE_ID_FILE):
        with open(DEVICE_ID_FILE, "r", encoding="utf-8") as file:
            return file.read().strip()

    device_id = str(uuid.uuid4())
    with open(DEVICE_ID_FILE, "w", encoding="utf-8") as file:
        file.write(device_id)

    return device_id
