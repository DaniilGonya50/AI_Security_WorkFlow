# SecureFlow backend — Django REST Framework

Единый локальный кейс SecureFlow: существующий фронтенд + Django REST Framework + сканеры SAST/SCA/Secrets + передача реальных находок в предоставленный ИИ-модуль.

## Что требуется

- Python 3.10+
- Git в PATH (для сканирования GitHub)
- Зависимости из `requirements.txt`

## Установка и запуск

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 127.0.0.1:8000
```

Фронтенд открывается по адресу `http://127.0.0.1:8000/`.

Скопируйте `.env.example` в `.env` и заполните нужные значения. Для ИИ и уведомлений создайте `.env` в корне проекта. Для облачной модели задайте `YANDEX_IAM_TOKEN` и `YANDEX_FOLDER_ID`; для локальной — запущенный Ollama и `OLLAMA_URL`/`OLLAMA_MODEL`. Для Telegram задай `TELEGRAM_BOT_TOKEN` в `.env`. В отдельном терминале запусти `python manage.py runtelegrambot`, открой своего бота и отправь `/start`. После этого в Telegram-ноде можно указать `@username` или числовой `chat_id`. Username работает только после регистрации пользователя командой `/start`: Telegram Bot API не позволяет боту первым начать личный диалог с пользователем только по username. Не публикуй токен бота. Сценарии сохраняются в SQLite и доступны через кнопку «Сценарии». JSON-файлы автоматически не скачиваются; результаты отображаются в интерфейсе; для почты — SMTP-переменные. Без этих ключей сканирование всё равно работает, а ИИ-модуль использует предусмотренный им fallback, если внешняя модель недоступна.

Файл `data/vulnerabilities.json` содержит десять локальных advisory-записей, в том числе пять зависимостей из учебного репозитория `TBagirov/training` и запись для безопасного контрольного примера. Это целевая стартовая выборка, а не исчерпывающая база CVE. Ожидаемый формат:

```json
{
  "vulnerabilities": [
    {
      "group": "com.example",
      "artifact": "library",
      "severity": "HIGH",
      "ranges": [{"lower": "1.0.0", "upper": "2.0.0", "lowerInclusive": true, "upperInclusive": false}]
    }
  ]
}
```

## API

### Запуск Git-сканирования

`POST /api/scan/start/git`

```json
{
  "workflow": [
    {"id": 1, "type": "projecttype", "parentid": [-1], "info": {"data": "https://github.com/owner/repository"}},
    {"id": 2, "type": "check", "parentid": [1], "info": {"type": "sast"}},
    {"id": 3, "type": "check", "parentid": [2], "info": {"type": "secrets"}},
    {"id": 4, "type": "check", "parentid": [3], "info": {"type": "sca"}}
  ]
}
```

### Запуск ZIP-сканирования

`POST /api/scan/start/upload` — `multipart/form-data`:

- `file`: ZIP-архив проекта
- `workflow_json`: JSON-массив графа (та же структура, что в поле `workflow` выше)

### Опрос результата

`GET /api/scan/status?session_id=<uuid>`

Во время работы:

```json
{"status": "Ok", "text": "Выполняется: check (sast)"}
```

При завершении:

```json
{
  "status": "End",
  "text": "Анализ завершен",
  "data": {
    "message_config": null,
    "llm_config": null,
    "findings": [
      {"type": "SAST", "line": 12, "file": "src/Main.kt", "severity": "HIGH"}
    ]
  }
}
```

При ошибке:

```json
{"status": "Error", "text": "Описание ошибки"}
```

## Сохранённая логика и ограничения

- `projecttype`, `trigger_button`, `trigger_schedule`, `message`, `llmtype`, `check` и `logic` распознаются так же, как в исходном движке.
- `message_config` и `llm_config` передаются в адаптер ИИ: `local` преобразуется в `ollama`, `cloud` — в `yandex`; `telegram` и `smtp` выбирают соответствующий канал. Итог ИИ добавляется в `data.ai_report`, исходные находки сканеров остаются в `data.findings`.
- Ноды `logic` в исходной версии пропускались; в переносе они тоже не исполняют ветвление.
- SAST теперь проверяет Kotlin, Java, JavaScript/TypeScript, Python, SQL, XML и Gradle-файлы по пяти группам эвристических правил. Secrets проверяет более широкий набор исходных и конфигурационных форматов, включая `.properties`, `.json`, `.env`, `.xml`, `.toml`, JavaScript и Python. Значения секретов в результат не записываются.
- SCA проверяет прямые зависимости в `build.gradle.kts`, `build.gradle` и `pom.xml`; обрабатывает обычные Gradle-объявления, многострочный `add(...)`, простые локальные переменные версий, `gradle.properties` и `gradle.lockfile`. Локальная база содержит десять advisory-записей, но не является полной CVE-базой: транзитивные зависимости и сложные version catalogs требуют дополнительной обработки. Для полноценной оценки подключайте регулярно обновляемый источник advisory.
- Для ZIP добавлены проверки traversal, symlink, числа файлов и суммарного распакованного размера. Git URL ограничен HTTPS-репозиториями GitHub.

## Важное для эксплуатации

Фоновый запуск сейчас реализован отдельным daemon-потоком, чтобы сохранить простую схему исходного приложения. Это подходит для локального запуска и первичной интеграции, но не гарантирует выполнение задач при перезапуске процесса и не предназначено для нескольких production workers. Для промышленного развёртывания вынесите `run_scan_background` в Celery/RQ и используйте PostgreSQL. Перед публичным запуском также добавьте аутентификацию, ограничения частоты запросов и изоляцию сканеров.

## Ограничения текущей связки

- Текущий интерфейс отправляет GitHub workflow. ZIP endpoint доступен напрямую через API, но кнопки выбора ZIP в предоставленном фронтенде нет.
- В исходном ИИ-модуле реализованы Telegram и Email; `webhook` из интерфейса пока не отправляет уведомление.
- Ветвление `logic` и расписание триггера не исполняются как автоматические правила: это ограничение исходного движка, сохранённое при интеграции.
- SCA использует локальный файл `data/vulnerabilities.json` с десятью advisory-записями. Это не полная база CVE; сканер проверяет явно объявленные прямые зависимости и их версии с учётом простых переменных Gradle и lockfile.
- Проверка кода и сборка Python-файлов выполнены. Запуск Django в среде сборки не удалось проверить, потому что здесь отсутствует Django и нет доступа к PyPI; локально зависимости устанавливаются командой `pip install -r requirements.txt`.

### Совместимость с Python

Проект рассчитан на Python 3.9 и новее. Для Python 3.9 используется Django 4.2.x; Django 5.x требует более новую версию Python.
