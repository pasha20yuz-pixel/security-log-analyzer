# Security Log Analyzer

CLI-инструмент на Python для анализа authentication logs и обнаружения подозрительной активности.

Проект разработан как портфолио-проект в области Python и информационной безопасности.

## Features

- Парсинг authentication logs
- Обнаружение brute-force атак
- Обнаружение password spraying
- Настраиваемый порог количества попыток
- Настраиваемое временное окно обнаружения
- Человекочитаемый вывод
- JSON-вывод
- Валидация CLI-параметров
- Автоматические тесты на pytest

## Quick Start

```bash
git clone https://github.com/pasha20yuz-pixel/security-log-analyzer.git
cd security-log-analyzer

python -m venv .venv
python -m pip install -e .

python -m seclog.cli examples/auth.log
```

## Detection

### Brute Force

Brute-force обнаруживается, когда один пользователь получает несколько неудачных попыток входа с одного IP-адреса в заданном временном окне.

Пример:

```text
admin ← 192.168.1.10
admin ← 192.168.1.10
admin ← 192.168.1.10
```

Результат:

```text
[HIGH] BRUTE_FORCE
User: admin
IP: 192.168.1.10
Failed attempts: 3
```

### Password Spraying

Password spraying обнаруживается, когда один IP-адрес выполняет неудачные попытки входа для нескольких разных пользователей в заданном временном окне.

Пример:

```text
10.0.0.50 → admin
10.0.0.50 → root
10.0.0.50 → test
```

Результат:

```text
[HIGH] PASSWORD_SPRAYING
User: *
IP: 10.0.0.50
Failed attempts: 3
```

## Installation

Клонировать репозиторий:

```bash
git clone https://github.com/pasha20yuz-pixel/security-log-analyzer.git
cd security-log-analyzer
```

Создать виртуальное окружение:

```bash
python -m venv .venv
```

Активировать виртуальное окружение.

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

Если выполнение PowerShell-скриптов ограничено политикой системы, можно использовать:

```powershell
.\.venv\Scripts\activate.bat
```

Установить проект:

```bash
python -m pip install -e .
```

Установить зависимости для тестирования:

```bash
pip install -r requirements.txt
```

## Usage

Базовый запуск:

```bash
python -m seclog.cli examples/auth.log
```

Пример результата:

```text
Security Log Analyzer
==============================
Events analyzed: 13
Alerts detected: 3

[HIGH] BRUTE_FORCE
User: admin
IP: 192.168.1.10
Failed attempts: 3

[HIGH] BRUTE_FORCE
User: root
IP: 10.0.0.5
Failed attempts: 3

[HIGH] PASSWORD_SPRAYING
User: *
IP: 10.0.0.50
Failed attempts: 3
```

## Configuration

### Threshold

Количество неудачных попыток, необходимое для создания alert:

```bash
python -m seclog.cli examples/auth.log --threshold 5
```

По умолчанию:

```text
threshold = 3
```

### Time Window

Временное окно обнаружения задаётся в секундах:

```bash
python -m seclog.cli examples/auth.log --window 120
```

Можно комбинировать параметры:

```bash
python -m seclog.cli examples/auth.log --threshold 5 --window 120
```

## JSON Output

Для интеграции с другими инструментами можно использовать JSON:

```bash
python -m seclog.cli examples/auth.log --format json
```

Пример:

```json
{
  "events_analyzed": 13,
  "alerts_detected": 3,
  "alerts": [
    {
      "alert_type": "BRUTE_FORCE",
      "severity": "HIGH",
      "username": "admin",
      "ip_address": "192.168.1.10",
      "failed_attempts": 3
    },
    {
      "alert_type": "BRUTE_FORCE",
      "severity": "HIGH",
      "username": "root",
      "ip_address": "10.0.0.5",
      "failed_attempts": 3
    },
    {
      "alert_type": "PASSWORD_SPRAYING",
      "severity": "HIGH",
      "username": "*",
      "ip_address": "10.0.0.50",
      "failed_attempts": 3
    }
  ]
}
```

## Testing

Проект покрыт автоматическими тестами с использованием pytest.

На текущем этапе проект содержит 18 автоматических тестов.

Запуск:

```bash
python -m pytest
```

Тесты проверяют:

- корректный парсинг логов;
- обработку некорректных данных;
- обнаружение brute-force;
- обнаружение password spraying;
- работу временного окна;
- пользовательские thresholds;
- работу CLI;
- CLI-параметры;
- загрузку log-файлов;
- преобразование alerts в JSON.

## Project Structure

```text
security-log-analyzer/
│
├── examples/
│   └── auth.log
│
├── src/
│   └── seclog/
│       ├── __init__.py
│       ├── analyzer.py
│       ├── cli.py
│       └── parser.py
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_cli.py
│   └── test_parser.py
│
├── .gitignore
├── pyproject.toml
├── README.md
└── requirements.txt
```

## Architecture

Проект разделён на несколько компонентов:

```text
                Authentication Log
                        │
                        ▼
                     Parser
                        │
                        ▼
                    LogEvent[]
                        │
                        ▼
                 Detection Engine
                  ┌─────┴─────┐
                  ▼           ▼
             Brute Force   Password
                           Spraying
                  │           │
                  └─────┬─────┘
                        ▼
                  SecurityAlert[]
                        │
                        ▼
                       CLI
                   ┌────┴────┐
                   ▼         ▼
                 Text       JSON
```

Такое разделение позволяет независимо расширять парсер, detection engine и интерфейс командной строки.

## Technologies

- Python 3.11
- pytest
- argparse
- JSON
- Git
- GitHub

## Future Improvements

Планируемые улучшения:

- обнаружение account enumeration;
- обнаружение подозрительных успешных входов;
- дополнительные типы security alerts;
- поддержка нескольких форматов логов;
- экспорт результатов в файл;
- более подробная информация об инцидентах;
- CI через GitHub Actions;
- расширение test coverage.

## Author

### Pavel Yuzhalkin

Saint Petersburg, Russia

[GitHub Repository](https://github.com/pasha20yuz-pixel/security-log-analyzer)
