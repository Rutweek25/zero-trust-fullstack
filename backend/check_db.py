import json
import os
from pathlib import Path
import sqlite3
import time
from datetime import datetime
from time_utils import now_ist

DB_FILE = Path(__file__).parent / "insider.db"


def check_database():
    """Check database status and contents"""
    db_file = str(DB_FILE)
    
    if not os.path.exists(db_file):
        print(f"✗ Database file not found: {db_file}")
        print("  Please run: python create_db.py")
        return False
    
    print(f"✓ Database file found: {db_file}")
    print(f"  Size: {os.path.getsize(db_file)} bytes")
    print(f"  Modified: {datetime.fromtimestamp(os.path.getmtime(db_file))}\n")
    
    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        
        # Check tables
        c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = c.fetchall()
        
        if tables:
            print("✓ Tables found:")
            for table in tables:
                table_name = table[0]
                c.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = c.fetchone()[0]
                print(f"  • {table_name}: {count} records")
                
                # Show schema
                c.execute(f"PRAGMA table_info({table_name})")
                columns = c.fetchall()
                for col in columns:
                    col_id, col_name, col_type, notnull, default, pk = col
                    pk_marker = " (PRIMARY KEY)" if pk else ""
                    print(f"      - {col_name}: {col_type}{pk_marker}")
        else:
            print("✗ No tables found in database")
            return False
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        print(f"✗ Database error: {e}")
        return False


def _usb_event_label(event_data: dict) -> tuple[str, str]:
    """Return (label, detail) for a USB event row."""
    raw_desc = str(event_data.get("description", "")).strip()
    event_type = None
    if "EventType" in raw_desc:
        try:
            event_type = int(raw_desc.split(":", 1)[1].strip())
        except (ValueError, IndexError):
            event_type = None

    if event_type == 2:
        return "USB inserted", raw_desc
    if event_type == 3:
        return "USB removed", raw_desc

    return "USB changed", raw_desc


def _usb_event_label_from_code(event_type: int | None) -> str:
    if event_type == 2:
        return "USB inserted"
    if event_type == 3:
        return "USB removed"
    return "USB changed"


def watch_usb_events_live() -> None:
    """Watch USB insert/remove events directly from Windows WMI."""
    try:
        import wmi  # type: ignore
    except Exception:
        print("✗ Live USB watcher requires 'wmi' package")
        print("  Install with: pip install wmi")
        print("  Falling back to DB telemetry watcher...\n")
        watch_usb_events_db()
        return

    print("Watching live USB events. Insert/remove a USB device to see output.")
    watcher = wmi.WMI().Win32_DeviceChangeEvent.watch_for()

    while True:
        try:
            event = watcher()
            event_type = getattr(event, "EventType", None)
            label = _usb_event_label_from_code(event_type)
            ts = now_ist().isoformat()
            print(f"[{ts}] {label} (EventType: {event_type})")
        except Exception as e:
            print(f"✗ Live watcher error: {e}")
            time.sleep(1)


def watch_usb_events_db(poll_seconds: int = 1) -> None:
    """Continuously print new USB telemetry events."""
    db_file = str(DB_FILE)

    if not os.path.exists(db_file):
        print(f"✗ Database file not found: {db_file}")
        print("  Please run: python create_db.py")
        return

    print("Watching DB USB telemetry events. Insert a USB device to see output.")
    last_id = 0

    while True:
        try:
            conn = sqlite3.connect(db_file)
            c = conn.cursor()
            c.execute(
                "SELECT id, device_id, collected_at, metrics FROM telemetry "
                "WHERE id > ? ORDER BY id ASC",
                (last_id,),
            )
            rows = c.fetchall()
            conn.close()

            for row in rows:
                row_id, device_id, collected_at, metrics = row
                last_id = max(last_id, row_id)

                if not metrics:
                    continue

                try:
                    metrics_json = json.loads(metrics)
                except json.JSONDecodeError:
                    continue

                usb_devices = metrics_json.get("usb_devices")
                if not usb_devices:
                    continue

                for event_data in usb_devices:
                    label, detail = _usb_event_label(event_data if isinstance(event_data, dict) else {})
                    ts = event_data.get("timestamp") if isinstance(event_data, dict) else None
                    ts = ts or collected_at
                    detail_text = f" ({detail})" if detail else ""
                    print(f"[{ts}] device_id={device_id} {label}{detail_text}")

        except sqlite3.Error as e:
            print(f"✗ Database error: {e}")

        time.sleep(poll_seconds)

if __name__ == "__main__":
    watch_usb_events_live()
