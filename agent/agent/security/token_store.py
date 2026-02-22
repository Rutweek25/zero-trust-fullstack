import getpass
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Optional


class SecureTokenStore:
    def __init__(self, token_file: str):
        self.token_file = Path(token_file)
        self.token_file.parent.mkdir(parents=True, exist_ok=True)

    def _restrict_permissions(self) -> None:
        if platform.system() != "Windows":
            try:
                os.chmod(self.token_file, 0o600)
            except Exception:
                pass
            return

        user_name = getpass.getuser()
        try:
            subprocess.run(
                ["icacls", str(self.token_file), "/inheritance:r"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                ["icacls", str(self.token_file), "/grant:r", f"{user_name}:(M)", "SYSTEM:(F)", "Administrators:(F)"],
                check=False,
                capture_output=True,
            )
        except Exception:
            pass

    def load(self) -> Optional[str]:
        if not self.token_file.exists():
            return None

        try:
            with open(self.token_file, "r", encoding="utf-8") as file:
                data = json.load(file)
            token = data.get("agent_token")
            return token if isinstance(token, str) and token.strip() else None
        except Exception:
            return None

    def save(self, token: str) -> None:
        payload = {"agent_token": token}
        with open(self.token_file, "w", encoding="utf-8") as file:
            json.dump(payload, file)
        self._restrict_permissions()

    def clear(self) -> None:
        try:
            if self.token_file.exists():
                self.token_file.unlink()
        except Exception:
            pass
