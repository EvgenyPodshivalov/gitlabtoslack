# GitLab → Slack: уведомления о событиях

Сервис принимает WebHook-и из GitLab и отправляет уведомления в Slack.

## Какие события обрабатываются

- создание задачи (issue)
- закрытие и повторное открытие задачи
- изменения назначенных исполнителей (assignees)
- изменения меток (labels)
- новые комментарии

### Комментарии

Для комментариев уведомления отправляются:
- автору задачи
- назначенному исполнителю
- пользователям, упомянутым в тексте (по маппингу GitLab → Slack)

## Конфигурация

Файл конфигурации по умолчанию: `config.yaml`. Можно указать путь через
переменную окружения `CONFIG_PATH`.

Пример `config.yaml.sample`:

```yaml
gitlab:
  # Опционально. Пустое значение отключает проверку токена.
  token: ""
slack_config:
  token: xoxp-xxxx
slack_channel:
  default: "#default_channel"
  close_issue: "#issue_channel"
  reopen_issue: "#issue_channel"
  new_issue: "#issue_channel"
  # update_assignes поддерживается для старых конфигов
  update_assignees: "#channel"
  update_labels: "#channel"
  new_comment: "#channel"
slack_users:
  GitLab_User1: Slack_User1
  GitLab_User2: Slack_User2
  GitLab_User3: Slack_User3
```

## Переменные окружения

- `CONFIG_PATH` — путь к файлу конфигурации (по умолчанию `config.yaml`)
- `DEFAULT_SLACK_USER` — получатель по умолчанию, если не указан канал

## Запуск через Docker

```dockerfile
FROM stelsik/gitlabtoslack

COPY config.yaml /app
```

## Запуск локально

```bash
python3 app.py
```

По умолчанию сервис слушает порт `5000`.

## Настройка WebHook в GitLab

Добавьте WebHook в GitLab, указав URL вида:

```
http://<host>:5000/webhook
```

Если в конфиге задан `gitlab.token`, тот же токен нужно указать в настройках WebHook.
