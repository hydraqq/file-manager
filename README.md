# Secure File Manager

Учебный проект по безопасной разработке веб-приложений.

## Технологии

- FastAPI + Uvicorn
- Pydantic v2
- Docker, Docker Compose
- Cryptography (Fernet)
- Bleach (XSS protection)
- pip-audit, Bandit

## Запуск

```bash
git clone https://github.com/hydraqq/file-manager.git
cd file_manager
cp .env.example .env
# Заполни .env своими секретами
docker-compose up -d
```

Документация API: `http://localhost:8000/docs`

## Генерация ключа шифрования

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

Скопируй вывод в `.env` как значение `ENCRYPTION_KEY`.

## API

| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| POST | /login | Вход |
| POST | /logout | Выход |
| POST | /registration | Регистрация |
| GET | /comments | Страница комментариев |
| POST | /comments | Добавить комментарий |
| GET | /files/my | Мои файлы |
| GET | /files/all | Все файлы (только admin) |
| POST | /files/upload | Загрузить файл |
| GET | /files/{id} | Информация о файле |
| DELETE | /files/{id} | Удалить файл |
| GET | /files/{id}/download | Скачать файл |
| GET | /cause_error | Тест обработчика ошибок |

## Пользователи по умолчанию

| Логин | Пароль | Роль |
|-------|--------|------|
| alice | Alice123! | user |
| bob | Bob123! | user |
| admin | Admin123! | admin |
