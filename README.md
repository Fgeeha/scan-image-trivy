# 🔍 Автоматическая проверка Docker-образов на уязвимости с помощью Trivy

Этот проект позволяет **автоматически сканировать Docker-образы** на наличие уязвимостей уровней `HIGH` и `CRITICAL` с помощью [Trivy](https://github.com/aquasecurity/trivy) и формировать:

- 📄 **JSON-отчёты** — для машинной обработки и CI/CD
- 📊 **Markdown-сводку** — для быстрого просмотра результатов
- 🌐 **HTML-отчёты** — для удобного чтения человеком

---

## 📂 Структура проекта

```

.
├── images.txt           # список образов для сканирования
├── scan\_trivy.sh        # скрипт для запуска Trivy и генерации отчётов
├── Makefile             # удобные команды
├── .gitlab-ci.yml       # пример интеграции в GitLab CI
└── reports/             # каталог для результатов сканирования
├── json/            # JSON-отчёты по каждому образу
├── html/            # HTML-отчёты по каждому образу
└── summary.md       # общая таблица по всем образам

````

---

## 📦 Настройка

1. Установите зависимости:
   - [Trivy](https://aquasecurity.github.io/trivy)
   - `jq` (для агрегации результатов)
   - `bash`

   > Если Trivy не установлен, можно использовать контейнерный режим (см. ниже).

2. Убедитесь, что скрипт исполняемый:
   ```bash
   chmod +x scan_trivy.sh
    ```


## 📝 Конфигурация списка образов
Надо скопировать `images.txt.example` -> `images.txt` и дополнить своими образами 

В файле `images.txt` перечислите образы в формате `image:tag`:

```text
minio/minio:RELEASE.2025-06-13T11-33-47Z
grafana/loki:3.5.5
```

---

## 🚀 Использование

### 1. Локальный запуск (Trivy установлен)

```bash
make scan
```

### 2. В контейнере (если Trivy не установлен)

```bash
make scan-docker
```

### 3. Очистка отчётов

```bash
make clean
```

---

## 📊 Результаты

После запуска вы получите:

* `reports/summary.md` — таблица с количеством HIGH/CRITICAL уязвимостей
* `reports/json/*.json` — детальные JSON-отчёты
* `reports/html/*.html` — читабельные HTML-страницы по каждому образу

Пример Markdown-сводки:

| Image            | Tag                            | HIGH | CRITICAL | Total | Scan Time           |
|------------------|--------------------------------| ---- | -------- | ----- | ------------------- |
| `minio/minio`    | `RELEASE.2025-06-13T11-33-47Z` | 12   | 1        | 13    | 2025-09-17T09:40:00 |
| `grafana/loki`   | `3.5.5`                        | 0    | 0        | 0     | 2025-09-17T09:41:00 |

---

## ⚙️ CI/CD интеграция

В GitLab можно запускать сканирование по расписанию или на каждый коммит.
Пример `.gitlab-ci.yml.example` уже включён в проект.

* Артефакты сохраняются в `reports/`
* Можно настроить **фейл пайплайна**, если найдены CRITICAL уязвимости (`--exit-code 1` в `scan_trivy.sh`)

---

## 🔐 Дополнительно

* Можно добавить **SARIF-отчёт** для загрузки в GitHub/GitLab Code Scanning:

  ```bash
  trivy image --format sarif --output report.sarif ...
  ```
* Можно настроить уведомления в Telegram/Slack о найденных критических уязвимостях.
* В `scan_trivy.sh` предусмотрен флаг `DOCKERIZED=true`, чтобы запускать Trivy через Docker без локальной установки.

---

## 📌 Пример использования для MinIO

Проверка последнего MinIO:

```bash
trivy image minio/minio:RELEASE.2025-09-07T16-13-09Z \
  --ignore-unfixed \
  --severity HIGH,CRITICAL \
  --format json \
  --output trivy-minio-report-last.json
```

В автоматическом режиме результат попадёт в:

* `reports/json/minio_minio_RELEASE.2025-06-13T11-33-47Z.json`
* `reports/html/minio_minio_RELEASE.2025-06-13T11-33-47Z.html`
* `reports/summary.md` (сводка)

---


