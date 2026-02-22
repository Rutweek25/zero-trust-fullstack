import datetime
from agent.time_utils import now_ist
import time
from collections import deque


# Global deduplication cache: stores recent events with timestamps
_recent_events = deque(maxlen=50)  # Keep last 50 events
_DEDUPE_WINDOW_SECONDS = 3  # Ignore duplicate events within 3 seconds


def _is_duplicate_event(event_type: int, timestamp: datetime.datetime) -> bool:
    """Check if this event was recently seen."""
    global _recent_events
    
    # Clean old events outside the deduplication window
    cutoff_time = timestamp - datetime.timedelta(seconds=_DEDUPE_WINDOW_SECONDS)
    while _recent_events and _recent_events[0][1] < cutoff_time:
        _recent_events.popleft()
    
    # Check if this event type was recently seen
    for prev_type, prev_time in _recent_events:
        if prev_type == event_type:
            return True
    
    # Not a duplicate - add to cache
    _recent_events.append((event_type, timestamp))
    return False


def monitor_usb(callback, stop_event=None) -> None:
    try:
        import wmi
        watcher = wmi.WMI().Win32_DeviceChangeEvent.watch_for()
    except Exception:
        while True:
            if stop_event and stop_event.is_set():
                return
            time.sleep(5)

    while True:
        if stop_event and stop_event.is_set():
            return

        event = watcher()
        event_type_code = getattr(event, 'EventType', None)
        timestamp = now_ist()
        
        # Skip duplicate events within the deduplication window
        if _is_duplicate_event(event_type_code, timestamp):
            continue
        
        event_data = {
            "event_type": "USB Change",
            "timestamp": timestamp.isoformat(),
            "description": f"EventType: {event_type_code}",
        }
        callback(event_data)
