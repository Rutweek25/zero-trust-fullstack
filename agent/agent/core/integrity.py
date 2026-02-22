import hashlib
from pathlib import Path


def _file_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def compute_manifest_hash(monitored_files: list[str]) -> str:
    digest = hashlib.sha256()
    for path in sorted(monitored_files):
        file_path = Path(path)
        if not file_path.exists():
            continue
        digest.update(path.encode("utf-8"))
        digest.update(_file_sha256(file_path).encode("utf-8"))
    return digest.hexdigest()


def verify_or_init_integrity(hash_file: str, monitored_files: list[str]) -> tuple[bool, str, str]:
    hash_path = Path(hash_file)
    hash_path.parent.mkdir(parents=True, exist_ok=True)

    current_hash = compute_manifest_hash(monitored_files)

    if not hash_path.exists():
        hash_path.write_text(current_hash, encoding="utf-8")
        return True, "initialized", current_hash

    expected_hash = hash_path.read_text(encoding="utf-8").strip()
    if expected_hash == current_hash:
        return True, "ok", current_hash

    return False, expected_hash, current_hash
