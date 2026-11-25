from __future__ import annotations
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath

ALLOWED_EXTS = {'.yml', '.yaml', '.sql', '.kt', '.kts', '.java', '.properties', '.xml', '.json', '.js', '.jsx', '.ts', '.tsx', '.py', '.gradle', '.toml', '.ini', '.cfg', '.conf', '.txt', '.env'}
SKIP_DIRS = {'.git', 'build', '.gradle', 'out', 'node_modules', '.idea'}
ALLOWED_NAMES = {'.env', '.env.local', '.env.example'}
GITHUB_RE = re.compile(r'^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$')
MAX_ZIP_FILES = 20_000
MAX_UNPACKED_BYTES = 250 * 1024 * 1024

class RepoFetchError(ValueError):
    pass

def validate_github_url(url: str) -> str:
    url = (url or '').strip()
    if not GITHUB_RE.fullmatch(url):
        raise RepoFetchError('Разрешены только публичные GitHub URL вида https://github.com/owner/repository')
    return url

def walk_filtered(root: Path) -> list[Path]:
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if (path.suffix.lower() in ALLOWED_EXTS or name.lower() in ALLOWED_NAMES) and path.is_file():
                result.append(path)
    return result

def _new_repo_dir(prefix: str) -> tuple[str, Path]:
    run_id = uuid.uuid4().hex
    base = Path(tempfile.gettempdir()) / 'secureflow_scans'
    base.mkdir(parents=True, exist_ok=True)
    target = base / f'{prefix}_{run_id}'
    target.mkdir(parents=False, exist_ok=False)
    return run_id, target

def clone_repo(url: str, timeout_s: int = 120) -> tuple[str, Path, list[Path]]:
    url = validate_github_url(url)
    run_id, root = _new_repo_dir('git')
    env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1'}
    command = [
        'git', '-c', 'core.hooksPath=/dev/null', 'clone', '--depth', '1',
        '--single-branch', '--no-tags', '--', url, str(root),
    ]
    try:
        subprocess.run(command, check=True, timeout=timeout_s, env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return run_id, root, walk_filtered(root)
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise RepoFetchError('Превышено время ожидания клонирования репозитория') from exc
    except (subprocess.CalledProcessError, OSError) as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise RepoFetchError('Не удалось клонировать GitHub-репозиторий') from exc

def extract_zip(zip_path: Path) -> tuple[str, Path, list[Path]]:
    run_id, root = _new_repo_dir('zip')
    total_size = 0
    try:
        with zipfile.ZipFile(zip_path, 'r') as archive:
            members = archive.infolist()
            if len(members) > MAX_ZIP_FILES:
                raise RepoFetchError('В архиве слишком много файлов')
            for member in members:
                # Не извлекаем абсолютные пути, ../ и символьные ссылки.
                member_path = PurePosixPath(member.filename.replace('\\', '/'))
                if member_path.is_absolute() or '..' in member_path.parts:
                    raise RepoFetchError('Архив содержит небезопасный путь')
                unix_mode = (member.external_attr >> 16) & 0xFFFF
                if (unix_mode & 0o170000) == 0o120000:
                    raise RepoFetchError('Символьные ссылки внутри ZIP запрещены')
                total_size += member.file_size
                if total_size > MAX_UNPACKED_BYTES:
                    raise RepoFetchError('Размер распакованного архива превышает 250 МБ')
                destination = (root / Path(*member_path.parts)).resolve()
                if not destination.is_relative_to(root.resolve()):
                    raise RepoFetchError('Архив пытается записать файл за пределами временной папки')
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, 'r') as source, destination.open('wb') as target:
                    shutil.copyfileobj(source, target)
        return run_id, root, walk_filtered(root)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise

def cleanup_repo(root: Path | None) -> None:
    if root:
        shutil.rmtree(root, ignore_errors=True)
