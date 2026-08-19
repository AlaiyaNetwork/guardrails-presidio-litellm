#!/usr/bin/env sh
set -eu
BASE="${1:-http://127.0.0.1:5002}"

echo '== /analyze (Unicode prefix + email) =='
curl -fsS "$BASE/analyze" \
  -H 'content-type: application/json' \
  -d '{"text":"Привет, напиши на alice@example.com","language":"ru","entities":["EMAIL_ADDRESS"]}'
echo

echo '== /anonymize =='
curl -fsS "$BASE/anonymize" \
  -H 'content-type: application/json' \
  -d '{"text":"Привет, напиши на alice@example.com","analyzer_results":[{"entity_type":"EMAIL_ADDRESS","start":18,"end":35,"score":1.0}]}'
echo
