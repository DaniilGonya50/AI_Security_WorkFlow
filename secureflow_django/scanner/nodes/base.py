from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

@dataclass
class NodeContext:
    files: list[Path]
    root: Path
    run_id: str

@dataclass
class Finding:
    type: str
    line: int
    file: str
    severity: str
    class_code: str | None = None
    end_line: int | None = None
    group: str | None = None
    artifact: str | None = None
    version: str | None = None
    advisory_ids: list[str] | None = None

class BaseNode:
    node_type = 'base'
    display_name = 'Базовый сканер'
    def run(self, context: NodeContext) -> list[Finding]:
        raise NotImplementedError

def relative_path(file: Path, root: Path) -> str:
    try:
        return file.relative_to(root).as_posix()
    except ValueError:
        return file.as_posix()
