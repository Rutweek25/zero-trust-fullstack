from datetime import datetime, timezone
from agent.time_utils import now_ist

import psutil


def collect_metrics() -> dict:
    metrics = {
        "timestamp": now_ist().isoformat(),
        "cpu": {},
        "memory": {},
        "disk": {},
        "processes": {},
        "network": {},
    }

    try:
        # Non-blocking CPU sampling (no interval blocking)
        metrics["cpu"] = {"percent": psutil.cpu_percent(interval=None)}
    except Exception:
        pass

    try:
        vm = psutil.virtual_memory()
        metrics["memory"] = {"virtual": {"percent": vm.percent, "used_mb": vm.used / (1024 ** 2)}}
    except Exception:
        pass

    try:
        disk = psutil.disk_usage("/")
        metrics["disk"] = {"root": {"percent": disk.percent, "used_gb": disk.used / (1024 ** 3)}}
    except Exception:
        pass

    try:
        metrics["processes"] = {"total": len(psutil.pids())}
    except Exception:
        pass

    try:
        metrics["network"] = {"connections": len(psutil.net_connections())}
    except Exception:
        pass

    return metrics
