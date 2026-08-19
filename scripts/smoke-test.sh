#!/usr/bin/env sh
set -eu

BASE="${1:-http://127.0.0.1:5002}"

fail() {
  echo "smoke test failed: $*" >&2
  exit 1
}

json_assert() {
  json="$1"
  expr="$2"
  printf '%s' "$json" | python3 -c "import json,sys; data=json.load(sys.stdin); assert $expr"
}

echo '== /healthz =='
health="$(curl -fsS "$BASE/healthz")"
printf '%s\n' "$health"
json_assert "$health" "data.get('status') == 'ok'" || fail '/healthz did not return status=ok'

echo '== /analyze (Unicode prefix + email) =='
analyze="$(curl -fsS "$BASE/analyze" \
  -H 'content-type: application/json' \
  -d '{"text":"Привет, напиши на alice@example.com","language":"ru","entities":["EMAIL_ADDRESS"]}')"
printf '%s\n' "$analyze"
json_assert "$analyze" "len(data) == 1 and data[0].get('entity_type') == 'EMAIL_ADDRESS' and data[0].get('start') == 18 and data[0].get('end') == 35" \
  || fail 'EMAIL_ADDRESS detection or Unicode offsets are incorrect'

echo '== /anonymize =='
anonymize="$(curl -fsS "$BASE/anonymize" \
  -H 'content-type: application/json' \
  -d '{"text":"Привет, напиши на alice@example.com","analyzer_results":[{"entity_type":"EMAIL_ADDRESS","start":18,"end":35,"score":1.0}]}')"
printf '%s\n' "$anonymize"
json_assert "$anonymize" "data.get('text') == 'Привет, напиши на <EMAIL_ADDRESS>' and len(data.get('items', [])) == 1 and data['items'][0].get('entity_type') == 'EMAIL_ADDRESS'" \
  || fail 'EMAIL_ADDRESS was not anonymized correctly'

echo '== /supportedentities =='
entities="$(curl -fsS "$BASE/supportedentities")"
printf '%s\n' "$entities"
json_assert "$entities" "'EMAIL_ADDRESS' in data" || fail 'EMAIL_ADDRESS is missing from supported entities'

echo 'smoke test passed'
