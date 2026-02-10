# Защищенный REST API с интеграцией в CI/CD

## Описание
Учебный REST API на Flask для лабораторной работы 1 по предмету 'Информационная безопасность' с аутентификацией через JWT, хранением данных в SQLite, мерами защиты от OWASP Top 10 и интеграцией security-сканеров в CI.

## Эндпоинты
**1) Авторизация пользователя** 

1. Пользователь отправляет POST запрос на `/auth/login`, содержащий логин и пароль.
2. Приложение ищет соответствие в БД по имени
3. Приложение сравнивает хэши паролей
4. При успешной проверке приложение формирует JWT-токен, содержащий id пользователя, имя пользователи, дату истечения годности токена
5. Приложение подписывает токен секретным ключом приложения 
6. Приложение возвращает токен в ответе
- `POST /auth/login` — получение JWT (json: {"username":"...","password":"..."})
```bash
curl -X POST http://127.0.0.1:5000/auth/login -H "Content-Type: application/json" -d "{\"username\":\"test\",\"password\":\"test123\"}"
```

**2) Доступ к защищённым ресурсам**

Эндпоинты, доступ к которым должен быть только у авторизованных пользователей защищены декоратором `@require_auth`,
который извлекает из запроса заголовок `Authorization`, в котором должен содержаться токен. Токен декодируется, проверяется его срок годности,
и, при успешной проверке, передается в функцию-обработчик.

- `GET /api/data` — защищённый эндпоинт, требует заголовок `Authorization: Bearer <token>`

```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." http://127.0.0.1:5000/api/data
```

**3) Регистрация пользователя** 

1. Пользователь отправляет POST запрос на `/auth/register`, содержащий логин и пароль.
2. Пароль проходит проверку длины
3. Пароль хэшируется через `bcrypt`
4. Запись сохраняется в БД
- `POST /auth/register` — регистрация (json: {"username":"...","password":"..."})

```bash
curl -X POST http://127.0.0.1:5000/auth/register -H "Content-Type: application/json" -d "{\"username\":\"test\",\"password\":\"test123\"}"
```

## Mеры защиты

### SQLi

Реализуется посредством использования SQLAlchemy при инициализации БД, и использовании ее ORM методов для запросов к БД
```python
# models.py
db = SQLAlchemy()

# app.py
user = User(username=username, password_hash=hash_password(password))
db.session.add(user)
db.session.commit()
```

### XSS

Для предотвращения XSS перед отправкой ответа от API, все данные оборачиваются в escape()
```python
def get_data(payload):
    users = User.query.all()
    result = []
    for user in users:
        result.append({
            "id": user.id,
            "username": escape(user.username),
            "created_at": user.created_at.isoformat()
        })
    return jsonify(result)
```

## Скриншот отчета SAST
![SAST](./img/SAST-correct.png)

## Скриншоты отчетов SCA
**Отчет с найденными уязвимостями**
![SCA](./img/SCA-error.png)
**Отчет без найденных уязвимостей**
![SCA](./img/SCA-correct.png)
