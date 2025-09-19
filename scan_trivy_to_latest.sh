#!/usr/bin/env bash
set -euo pipefail

IMAGES_FILE="${1:-images.txt}"
OUT_DIR="${2:-reports}"
SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
IGNORE_UNFIXED="${IGNORE_UNFIXED:-true}"
DOCKERIZED="${DOCKERIZED:-false}"   # если trivy не установлен локально, можно запустить в контейнере
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
COMPARE_LATEST="${COMPARE_LATEST:-true}"  # сравнивать ли с :latest

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
> Сравнение с тегом `latest`, если доступен.

| Image | Tag | HIGH | CRITICAL | Total | Latest HIGH | Latest CRIT | Latest Total | Δ Total (tag→latest) | Same ImageID |
|------:|:----|-----:|---------:|------:|------------:|------------:|-------------:|---------------------:|:------------:|
EOF

run_trivy() {
  local ref="$1" out="$2"
  if [[ "$DOCKERIZED" == "true" ]]; then
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$(pwd)/$JSON_DIR":/json \
      "$TRIVY_IMAGE" image "$ref" \
        ${IGNORE_UNFIXED:+--ignore-unfixed} \
        --severity "$SEVERITY" \
        --format json \
        --output "/json/$out" || true
  else
    trivy image "$ref" \
      ${IGNORE_UNFIXED:+--ignore-unfixed} \
      --severity "$SEVERITY" \
      --format json \
      --output "$JSON_DIR/$out" || true
  fi
}

count_from_json() {
  local json="$1"
  # HIGH
  jq '[.. | objects? | select(.Severity? == "HIGH")] | length' "$json"
}

count_crit_from_json() {
  local json="$1"
  jq '[.. | objects? | select(.Severity? == "CRITICAL")] | length' "$json"
}

image_id_from_json() {
  local json="$1"
  jq -r '.Metadata.ImageID // .ArtifactID // empty' "$json"
}

html_from_json() {
  local json="$1" title="$2" out_html="$3"
  jq -r --arg TITLE "$title" '
    def row:
      "<tr><td>" + (.VulnerabilityID // "-") + "</td><td>" + (.PkgName // "-") + "</td><td>" + (.InstalledVersion // "-") + "</td><td>" + (.FixedVersion // "-") + "</td><td>" + (.Severity // "-") + "</td><td>" + (.Title // "-") + "</td></tr>";
    def rows:
      (.. | objects? | select(has("VulnerabilityID"))) | row;
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Trivy " + $TITLE + "</title></head><body>" +
    "<h1>Trivy report: " + $TITLE + "</h1>" +
    "<table border=1 cellpadding=6 cellspacing=0>" +
    "<thead><tr><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Title</th></tr></thead><tbody>" +
    (rows // "") +
    "</tbody></table></body></html>"
  ' "$json" > "$out_html"
}

scan_one() {
  local full="$1"
  local img="${full%%:*}"
  local tag="${full#*:}"

  # Имя файла (без слэшей и двоеточий)
  local safe="${full//\//_}"; safe="${safe//:/_}"
  local json_tag="${safe}.json"
  local html_tag="${safe}.html"

  echo "→ Сканирую $full ..."
  run_trivy "$full" "$json_tag"

  local path_tag="$JSON_DIR/$json_tag"
  if [[ ! -s "$path_tag" ]]; then
    echo "Нет JSON-отчёта для $full, пропускаю."
    return
  fi

  local high crit total
  high=$(count_from_json "$path_tag")
  crit=$(count_crit_from_json "$path_tag")
  total=$(( high + crit ))
  local id_tag
  id_tag=$(image_id_from_json "$path_tag" || true)

  html_from_json "$path_tag" "$full" "$HTML_DIR/$html_tag"

  # По умолчанию — нет latest
  local latest_ref="${img}:latest"
  local safe_latest="${img//\//_}_latest"
  local json_latest="${safe_latest}.json"
  local html_latest="${safe_latest}.html"
  local high_l="N/A" crit_l="N/A" total_l="N/A" id_latest="" same_id="N/A" delta_total="N/A"

  if [[ "$COMPARE_LATEST" == "true" ]]; then
    echo "  ↳ Сравниваю с ${latest_ref} ..."
    run_trivy "$latest_ref" "$json_latest"

    local path_latest="$JSON_DIR/$json_latest"
    if [[ -s "$path_latest" ]]; then
      high_l=$(count_from_json "$path_latest")
      crit_l=$(count_crit_from_json "$path_latest")
      total_l=$(( high_l + crit_l ))
      id_latest=$(image_id_from_json "$path_latest" || true)
      [[ -n "$id_tag" && -n "$id_latest" && "$id_tag" == "$id_latest" ]] && same_id="YES" || same_id="NO"
      if [[ "$total_l" =~ ^[0-9]+$ ]]; then
        delta_total=$(( total_l - total ))
      fi
      html_from_json "$path_latest" "$latest_ref" "$HTML_DIR/$html_latest"
    else
      echo "  ! Не удалось получить отчёт для ${latest_ref} (тег может отсутствовать или репозиторий приватный)."
    fi
  fi

  local ts
  ts=$(date -Iseconds)
  printf '| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
    "$img" "$tag" "$high" "$crit" "$total" "$high_l" "$crit_l" "$total_l" "$delta_total" "$same_id" >> "$MD_FILE"
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
