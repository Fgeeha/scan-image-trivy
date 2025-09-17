#!/usr/bin/env bash
set -euo pipefail

IMAGES_FILE="${1:-images.txt}"
OUT_DIR="${2:-reports}"
SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
IGNORE_UNFIXED="${IGNORE_UNFIXED:-true}"
DOCKERIZED="${DOCKERIZED:-false}"   # если trivy не установлен локально, можно запустить в контейнере
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"

# Подготовка каталогов
JSON_DIR="$OUT_DIR/json"
HTML_DIR="$OUT_DIR/html"
MD_FILE="$OUT_DIR/summary.md"

mkdir -p "$JSON_DIR" "$HTML_DIR"
: > "$MD_FILE"

# Проверка зависимостей
need() { command -v "$1" >/dev/null 2>&1 || { echo "Требуется $1"; exit 1; }; }
if [[ "$DOCKERIZED" != "true" ]]; then
  need trivy
fi
need jq
need date

# Заголовок сводного отчёта
cat > "$MD_FILE" <<'EOF'
# Trivy Security Report (HIGH, CRITICAL)

> Фильтры: `--ignore-unfixed`, `--severity HIGH,CRITICAL`

| Image | Tag | HIGH | CRITICAL | Total | Scan Time |
|------:|:----|-----:|---------:|------:|:----------|
EOF

scan_one() {
  local full="$1"
  local img="${full%%:*}"
  local tag="${full#*:}"

  # Имя файла (без слэшей и двоеточий)
  local safe="${full//\//_}"
  safe="${safe//:/_}"

  # Команда Trivy
  if [[ "$DOCKERIZED" == "true" ]]; then
    # Нужен docker.sock для анализа локальных образов/кэша
    # И общий том для отчётов
    CMD=(docker run --rm
      -v /var/run/docker.sock:/var/run/docker.sock
      -v "$(pwd)/$JSON_DIR":/json
      "$TRIVY_IMAGE"
      image "$full"
      --ignore-unfixed
      --severity "$SEVERITY"
      --format json
      --output "/json/${safe}.json")
  else
    CMD=(trivy image "$full"
      --ignore-unfixed
      --severity "$SEVERITY"
      --format json
      --output "${JSON_DIR}/${safe}.json")
  fi

  echo "→ Сканирую $full ..."
  if ! "${CMD[@]}" ; then
    echo "ВНИМАНИЕ: Trivy вернул ненулевой код для $full (уязвимости найдены/ошибка). Продолжаю сбор отчёта."
  fi

  local json="${JSON_DIR}/${safe}.json"
  if [[ ! -s "$json" ]]; then
    echo "Нет JSON-отчёта для $full, пропускаю агрегацию."
    return
  fi

  # Подсчёт уязвимостей по severity
  local high crit total
  high=$(jq '[.. | objects? | select(.Severity? == "HIGH")] | length' "$json")
  crit=$(jq '[.. | objects? | select(.Severity? == "CRITICAL")] | length' "$json")
  total=$(( high + crit ))
  local ts
  ts=$(date -Iseconds)

  printf '| `%s` | `%s` | %d | %d | %d | %s |\n' "$img" "$tag" "$high" "$crit" "$total" "$ts" >> "$MD_FILE"

  # HTML-отчёт (простой): список CVE таблицей
  local html="$HTML_DIR/${safe}.html"
  jq -r '
    def row:
      "<tr><td>" + (.VulnerabilityID // "-") + "</td><td>" + (.PkgName // "-") + "</td><td>" + (.InstalledVersion // "-") + "</td><td>" + (.FixedVersion // "-") + "</td><td>" + (.Severity // "-") + "</td><td>" + (.Title // "-") + "</td></tr>";
    def rows:
      (.. | objects? | select(has("VulnerabilityID"))) | row;
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Trivy '"$full"'</title></head><body>" +
    "<h1>Trivy report: '"$full"'</h1>" +
    "<p>Фильтры: --ignore-unfixed; severities: '"$SEVERITY"'</p>" +
    "<table border=1 cellpadding=6 cellspacing=0>" +
    "<thead><tr><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Title</th></tr></thead><tbody>" +
    (rows // "") +
    "</tbody></table></body></html>"
  ' "$json" > "$html"
}

# Основной цикл
if [[ ! -f "$IMAGES_FILE" ]]; then
  echo "Не найден $IMAGES_FILE"
  exit 1
fi

while IFS= read -r line; do
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  scan_one "$line"
done < "$IMAGES_FILE"

echo
echo "Готово:"
echo "  - Сводка: $MD_FILE"
echo "  - JSON на образ: $JSON_DIR/*.json"
echo "  - HTML на образ: $HTML_DIR/*.html"
