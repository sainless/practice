# Анализатор Apache логов

## Быстрый старт

### Установка зависимостей
```bash
pip install -r requirements.txt
```

### Основные команды

#### 1. Импорт логов в базу данных
```bash
python cli.py parse
```
*Парсит файл access.log из папки logs и сохраняет в SQLite базу*

#### 2. Просмотр логов
```bash
python cli.py show [опции]
```

Доступные опции фильтрации:
| Опция         | Пример                      | Описание                     |
|---------------|-----------------------------|------------------------------|
| `--ip`        | `--ip 192.168.1.1`          | Фильтр по IP-адресу          |
| `--keyword`   | `--keyword login`           | Поиск по URL                 |
| `--date-from` | `--date-from 2024-01-01`    | Начальная дата периода       |
| `--date-to`   | `--date-to 2024-01-31`      | Конечная дата периода        |
| `--limit`     | `--limit 200`               | Количество записей (по умолчанию 100) |

### Расположение файлов
| Файл/Папка         | Путь               |
|--------------------|--------------------|
| Логи Apache        | `./logs/access.log`|
| База данных SQLite | `./logs.db`        |
| Конфигурация       | `./config.ini`     |

### Примеры использования

**Показать последние 50 запросов от конкретного IP:**
```bash
python cli.py show --ip 192.168.1.5 --limit 50
```

**Найти все обращения к API за январь 2024:**
```bash
python cli.py show --keyword /api/ --date-from 2024-01-01 --date-to 2024-01-31
```
