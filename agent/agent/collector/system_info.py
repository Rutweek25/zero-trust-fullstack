import datetime
from agent.time_utils import now_ist
import platform
import socket
import uuid


def _mac_address() -> str:
    mac = uuid.getnode()
    return ":".join(["{:02x}".format((mac >> shift) & 0xFF) for shift in range(0, 48, 8)][::-1])


def get_registration_info() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os_version": f"{platform.system()} {platform.release()} ({platform.version()})",
        "system_info": {
            "mac_address": _mac_address(),
            "cpu_model": platform.processor() or "unknown",
            "total_memory_gb": None,
        },
    }


def get_system_info() -> dict:
    hostname = socket.gethostname()

    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "Unknown"

    mac_address = _mac_address()

    return {
        "event_type": "System Info",
        "hostname": hostname,
        "ip_address": ip_address,
        "os_name": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "mac_address": mac_address,
        "timestamp": now_ist().isoformat(),
    }
