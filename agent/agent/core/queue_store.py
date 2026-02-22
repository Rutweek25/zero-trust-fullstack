import json
import threading
from pathlib import Path
from typing import Optional


class LocalQueueStore:
    def __init__(self, queue_file: str, max_items: int = 1000):
        self.queue_file = Path(queue_file)
        self.max_items = max_items
        self.lock = threading.Lock()
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> list[dict]:
        if not self.queue_file.exists():
            return []

        try:
            with open(self.queue_file, "r", encoding="utf-8") as file:
                data = json.load(file)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _write(self, items: list[dict]) -> None:
        with open(self.queue_file, "w", encoding="utf-8") as file:
            json.dump(items, file, indent=2)

    def enqueue(self, item: dict) -> None:
        with self.lock:
            items = self._read()
            items.append(item)
            if len(items) > self.max_items:
                items = items[-self.max_items :]
            self._write(items)

    def peek(self) -> Optional[dict]:
        with self.lock:
            items = self._read()
            return items[0] if items else None

    def pop(self) -> Optional[dict]:
        with self.lock:
            items = self._read()
            if not items:
                return None
            first = items.pop(0)
            self._write(items)
            return first

    def size(self) -> int:
        with self.lock:
            return len(self._read())
