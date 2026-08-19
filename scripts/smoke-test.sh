#!/usr/bin/env sh
set -eu

BASE="${1:-http://127.0.0.1:5002}"

fail() {
  echo "smoke test failed: $*" >&2
  exit 1
}

echo '== /healthz =='
health="$(curl -fsS "$BASE/healthz")"
printf '%s\n' "$health"

echo '== /analyze (Unicode prefix + email) =='
analyze="$(curl -fsS "$BASE/analyze" \
  -H 'content-type: application/json' \
  -d '{"text":"Привет, напиши на alice@example.com","language":"ru","entities":["EMAIL_ADDRESS"]}')"
printf '%s\n' "$analyze"
printf '%s' "$analyze" | grep -q '"entity_type":"EMAIL_ADDRESS"' || fail 'EMAIL_ADDRESS was not detected'
printf '%s' "$analyze" | grep -q '"start":18' || fail 'Unicode start offset is not 18'
printf '%s' "$analyze" | grep -q '"end":35' || fail 'Unicode end offset is not 35'

echo '== /anonymize =='
anonymize="$(curl -fsS "$BASE/anonymize" \
  -H 'content-type: application/json' \
  -d '{"text":"Привет, напиши на alice@example.com","analyzer_results":[{"entity_type":"EMAIL_ADDRESS","start":18,"end":35,"score":1.0}]}')"
printf '%s\n' "$anonymize"
printf '%s' "$anonymize" | grep -q '<EMAIL_ADDRESS>' || fail 'EMAIL_ADDRESS was not anonymized'

echo '== /supportedentities =='
entities="$(curl -fsS "$BASE/supportedentities")"
printf '%s\n' "$entities"
printf '%s' "$entities" | grep -q 'EMAIL_ADDRESS' || fail 'EMAIL_ADDRESS is missing from supported entities'

echo 'smoke test passed'
