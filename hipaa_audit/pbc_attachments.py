from __future__ import annotations

import re
from pathlib import Path


def attachment_dir(repo_path: Path, request_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_-]", "", request_id)
    return repo_path / "compliance" / "pbc-attachments" / safe


def save_attachment(repo_path: Path, request_id: str, filename: str, data: bytes) -> str:
    safe_name = Path(filename).name
    if ".." in safe_name or not safe_name:
        raise ValueError("Invalid filename")
    dest_dir = attachment_dir(repo_path, request_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe_name
    dest.write_bytes(data)
    return str(dest.relative_to(repo_path))


def list_attachments(repo_path: Path, request_id: str) -> list[Path]:
    d = attachment_dir(repo_path, request_id)
    return sorted(d.glob("*")) if d.is_dir() else []
