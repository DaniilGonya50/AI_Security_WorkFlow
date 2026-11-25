import asyncio
import shutil
import threading
import uuid
from pathlib import Path
from django.conf import settings
from django.db import close_old_connections
from .models import ScanSession
from .repo_fetch import clone_repo, extract_zip, cleanup_repo, RepoFetchError
from .nodes.base import NodeContext
from .workflow_engine import WorkflowEngine, WorkflowError
from ai_module.main_ai import analyze_findings


def _update(session_id, **values):
    ScanSession.objects.filter(session_id=session_id).update(**values)


def _run_async(coro):
    return asyncio.run(coro)


def run_scan_background(session_id: str, source, source_type: str, workflow: list[dict]):
    close_old_connections()
    repo_root = None
    try:
        _update(session_id, status='running', stage='cloning' if source_type == 'git' else 'walking',
                current_text='Клонирование репозитория...' if source_type == 'git' else 'Распаковка архива...')
        if source_type == 'git':
            run_id, repo_root, files = clone_repo(source)
        elif source_type == 'zip':
            run_id, repo_root, files = extract_zip(Path(source))
        else:
            raise RepoFetchError('Неизвестный тип источника (ожидается git или zip)')

        _update(session_id, current_text=f'Найдено файлов: {len(files)}', stage='validating', progress=10)
        kotlin_files = [path for path in files if path.suffix.lower() == '.kt']
        gradle_files = [path for path in files if path.name.lower() == 'build.gradle.kts']
        if not kotlin_files or not gradle_files:
            raise WorkflowError('Репозиторий не похож на Kotlin/Spring Boot + Gradle: нужны .kt и build.gradle.kts')

        _update(session_id, current_text='Парсинг Kotlin-файлов...', stage='parsing', progress=15)
        # Оставлено как этап подготовки; результаты метаданных в исходной версии не использовались.
        for path in kotlin_files:
            try:
                path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue

        _update(session_id, current_text='Запуск проверок безопасности...', stage='scanning', progress=20)
        context = NodeContext(files=files, root=repo_root, run_id=run_id)
        engine = WorkflowEngine(settings.VULNERABILITIES_DB)
        session = ScanSession.objects.get(session_id=session_id)
        _run_async(engine.execute_graph(workflow, context, session))

        # Передаём реальные результаты сканеров в существующий ИИ-модуль.
        # Формат адаптируется к контракту AIAnalyzer: type/priority/locate.
        if session.status != 'error' and session.final_data:
            _update(session_id, current_text='ИИ анализирует найденные уязвимости...', stage='ai_analysis', progress=96)
            findings_for_ai = {}
            category_map = {'SECRET': 'secrets', 'SAST': 'logic', 'SCA': 'sca'}
            for number, finding in enumerate(session.final_data.get('findings', []), start=1):
                category = category_map.get(str(finding.get('type', '')).upper())
                if not category:
                    continue
                relative_file = finding.get('file', 'unknown')
                line_number = finding.get('line', 1)
                # Для SAST передаём контекст строки; секреты намеренно маскируем,
                # чтобы не отправлять реальные ключи/пароли во внешнюю модель.
                code_context = ''
                extra_fields = {}
                class_code = finding.get('class_code')
                if class_code:
                    extra_fields['class'] = class_code
                if finding.get('end_line'):
                    extra_fields['endLine'] = finding.get('end_line')
                if category == 'sca':
                    extra_fields.update({
                        'group': finding.get('group') or 'unknown',
                        'artifact': finding.get('artifact') or 'unknown',
                        'version': finding.get('version') or 'unknown',
                        'advisoryIds': finding.get('advisory_ids') or ['не указан'],
                    })
                if category == 'logic':
                    try:
                        source_lines = (repo_root / relative_file).read_text(encoding='utf-8', errors='replace').splitlines()
                        if isinstance(line_number, int) and 1 <= line_number <= len(source_lines):
                            code_context = source_lines[line_number - 1][:500]
                            import re
                            code_context = re.sub(
                                r'''(?i)(password|passwd|pwd|api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|authorization)\s*[:=]\s*(['"])[^'"]*\2''',
                                r"\1=\2[СКРЫТО]\2", code_context
                            )
                            code_context = re.sub(r'(?i)Bearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}', 'Bearer [СКРЫТО]', code_context)
                            code_context = re.sub(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', '[JWT СКРЫТ]', code_context)
                            code_context = re.sub(r'(AKIA|ASIA)[A-Z0-9]{16}', '[КЛЮЧ СКРЫТ]', code_context)
                    except (OSError, TypeError, ValueError):
                        pass
                elif category == 'secrets':
                    code_context = '[ЗНАЧЕНИЕ СЕКРЕТА СКРЫТО]'
                findings_for_ai[str(number)] = {
                    'priority': finding.get('severity', 'MEDIUM'),
                    'type': category,
                    'locate': [{
                        'file': relative_file,
                        'line': line_number,
                        'endLine': finding.get('end_line') or line_number,
                        'code': code_context,
                    }],
                    **extra_fields,
                }

            message_config = session.final_data.get('message_config') or {}
            llm_config = session.final_data.get('llm_config') or {}
            channel_type = str(message_config.get('type', '')).lower()
            raw_recipient = message_config.get('data')
            if isinstance(raw_recipient, dict):
                recipient = (
                    raw_recipient.get('chat_id') or raw_recipient.get('recipient') or
                    raw_recipient.get('username') or raw_recipient.get('data') or ''
                )
            else:
                recipient = (raw_recipient or message_config.get('recipient') or
                             message_config.get('username') or message_config.get('chat_id') or '')
            recipient = str(recipient).strip()
            channel_map = {'telegram': 'telegram', 'smtp': 'email', 'email': 'email'}
            channel = channel_map.get(channel_type, 'none')
            provider_map = {'local': 'ollama', 'cloud': 'yandex', 'ollama': 'ollama', 'yandex': 'yandex'}
            provider = provider_map.get(str(llm_config.get('type', '')).lower())

            try:
                ai_result = _run_async(analyze_findings(
                    findings=findings_for_ai,
                    channel=channel,
                    recipient=recipient,
                    provider=provider,
                    run_id=str(session_id),
                ))
                session.final_data['ai_report'] = ai_result
            except Exception as ai_exc:
                # Ошибка внешнего ИИ/уведомления не уничтожает результаты сканеров.
                session.final_data['ai_error'] = str(ai_exc)

            session.status = 'ended'
            session.stage = 'done'
            session.progress = 100
            session.current_text = 'Сканирование и анализ завершены'

        session.save(update_fields=['status', 'stage', 'progress', 'current_text', 'final_data', 'data_ready', 'updated_at'])
    except Exception as exc:
        # Текст ошибки сохраняется для фронтенда; подробности исключения остаются в серверном логе.
        _update(session_id, status='error', stage='error', current_text='Сканирование завершилось с ошибкой',
                error_text=str(exc), progress=0)
    finally:
        cleanup_repo(repo_root)
        if source_type == 'zip' and source:
            try:
                Path(source).unlink(missing_ok=True)
            except OSError:
                pass
        close_old_connections()


def start_scan(session: ScanSession, source, source_type: str, workflow: list[dict]):
    thread = threading.Thread(
        target=run_scan_background,
        args=(str(session.session_id), source, source_type, workflow),
        daemon=True,
        name=f'scan-{session.session_id}',
    )
    thread.start()
