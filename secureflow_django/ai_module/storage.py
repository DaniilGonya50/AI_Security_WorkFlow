from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional
from .config import logger


def normalize_username(value: str) -> str:
    return str(value or '').strip().lstrip('@').strip().casefold()


class UserStorage:
    def __init__(self, storage_file=None):
        if storage_file is None:
            storage_file = os.getenv('TELEGRAM_USERS_FILE') or (Path(__file__).resolve().parent / 'users.json')
        self.storage_file = str(storage_file)
        self.users: dict[str, dict] = {}
        self._load()

    def _load(self):
        path = Path(self.storage_file)
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
            self.users = payload if isinstance(payload, dict) else {}
            logger.info('Telegram storage loaded: %s registered users', len(self.users))
        except (OSError, ValueError) as exc:
            logger.error('Cannot load Telegram users storage: %s', exc)
            self.users = {}

    def _save(self):
        path = Path(self.storage_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temp = path.with_suffix(path.suffix + '.tmp')
            temp.write_text(json.dumps(self.users, ensure_ascii=False, indent=2), encoding='utf-8')
            os.replace(temp, path)
        except OSError as exc:
            logger.error('Cannot save Telegram users storage: %s', exc)

    def add_user(self, chat_id: int, username: str | None, first_name: str | None) -> None:
        clean = normalize_username(username)
        key = clean or f'user_{chat_id}'
        self.users[key] = {
            'chat_id': int(chat_id),
            'username': str(username or '').lstrip('@'),
            'first_name': first_name or 'User',
        }
        self._save()
        logger.info('Registered Telegram user chat_id=%s username=%s', chat_id, username or '(no username)')

    def get_chat_id_by_username(self, username: str) -> Optional[int]:
        wanted = normalize_username(username)
        if not wanted:
            return None
        for key, data in self.users.items():
            stored = normalize_username(data.get('username') or key)
            if stored == wanted:
                try:
                    return int(data['chat_id'])
                except (KeyError, TypeError, ValueError):
                    return None
        return None

    def list_users(self) -> list[dict]:
        return [{'username': data.get('username') or key, **data} for key, data in self.users.items()]


def resolve_recipient(identifier, storage: UserStorage) -> Optional[int]:
    if isinstance(identifier, dict):
        identifier = (identifier.get('chat_id') or identifier.get('recipient') or
                      identifier.get('username') or identifier.get('data') or '')
    if identifier is None:
        return None
    value = str(identifier).strip()
    if not value:
        return None
    if value.lstrip('-').isdigit():
        try:
            return int(value)
        except ValueError:
            return None
    return storage.get_chat_id_by_username(value)
