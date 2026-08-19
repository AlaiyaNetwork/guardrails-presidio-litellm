# guardrails-presidio-litellm

Presidio-compatible HTTP adapter around the detection engine from
[`cloud-ru-tech/guardrails-llm-filter`](https://github.com/cloud-ru-tech/guardrails-llm-filter),
intended as a drop-in PII backend for LiteLLM.

> **Upstream attribution:** this project is explicitly based on
> [`cloud-ru-tech/guardrails-llm-filter`](https://github.com/cloud-ru-tech/guardrails-llm-filter).
> The Docker build pins and compiles the original Cloud.ru rule loader, registry,
> regex scanner, validators, and bundled rule sets. The upstream project is
> Apache-2.0 licensed; its `LICENSE` and `NOTICE` are preserved in the image.

The goal is to keep the existing external topology unchanged:

```text
Client -> LiteLLM -> LLM provider
           |
           +-> Presidio-compatible guardrail API
                    |
                    +-> Cloud.ru guardrails regex/validator engine
```

LiteLLM still uses `guardrail: presidio`. You only point the existing Presidio
analyzer/anonymizer URLs to this service.

## Why

`guardrails-llm-filter` has a fast deterministic Go engine with a broad ruleset
for PII, credentials, API keys, access tokens, IP addresses, payment data and
Russian identifiers. The original project is designed primarily as a transparent
LLM reverse proxy. This project exposes that engine through Presidio-compatible
REST contracts instead, so LiteLLM remains the only client-facing gateway.

## Implemented Presidio compatibility

The service implements the contracts used by LiteLLM and common Presidio REST clients:

- `POST /analyze`
- `POST /anonymize`
- `GET /supportedentities`
- `GET /recognizers`
- `GET /anonymizers`
- `GET /deanonymizers`
- `GET /health` and `GET /healthz`

`/analyze` returns Presidio-style `entity_type`, `start`, `end`, and `score`. Cloud.ru scanner offsets are UTF-8 byte offsets; the adapter converts them to Unicode code-point offsets before returning them. This is important for Cyrillic and other non-ASCII text because LiteLLM applies Presidio offsets to Python strings.

The engine is deterministic, so accepted regex+validator matches are reported with `score: 1.0`.

`/anonymize` supports `replace`, `redact`, `mask`, and `hash` (`sha256` / `sha512`). Encryption and request-scoped ad-hoc recognizers are not implemented yet. Unknown request fields are tolerated for forward compatibility.

## Build

The build is intentionally pinned to upstream revision:

```text
bbd6f27467a53ff3869b59449edf4209f85ae675
```

```bash
docker build --build-arg UPSTREAM_REF=bbd6f27467a53ff3869b59449edf4209f85ae675 -t guardrails-presidio-litellm .
docker run --rm -p 5002:5002 guardrails-presidio-litellm
```

Or run `docker compose up --build`.

## LiteLLM configuration

```yaml
guardrails:
  - guardrail_name: pii_masking
    litellm_params:
      guardrail: presidio
      mode: pre_call
      default_on: true
      output_parse_pii: true

environment_variables:
  PRESIDIO_ANALYZER_API_BASE: http://guardrails-presidio:5002
  PRESIDIO_ANONYMIZER_API_BASE: http://guardrails-presidio:5002
```

A copy is available at [`examples/litellm/config.yaml`](examples/litellm/config.yaml).

With `output_parse_pii: true`, LiteLLM can continue to create request-scoped numbered tokens and restore them on output, while this service replaces Presidio as the analyzer/anonymizer backend.

## API examples

```bash
curl http://localhost:5002/analyze \
  -H 'content-type: application/json' \
  -d '{"text":"Привет, напиши на alice@example.com","language":"ru","entities":["EMAIL_ADDRESS"]}'
```

```json
[{"entity_type":"EMAIL_ADDRESS","start":18,"end":35,"score":1}]
```

## Entity names

Common Cloud.ru placeholders are normalized to conventional Presidio names:

| Cloud.ru | Presidio-compatible |
|---|---|
| `EMAIL` | `EMAIL_ADDRESS` |
| `PHONE` / `RU_PHONE` | `PHONE_NUMBER` |
| `CARD` / `PAYMENT_CARD` | `CREDIT_CARD` |
| `IPV4` / `IPV6` | `IP_ADDRESS` |
| `IBAN` | `IBAN_CODE` |

Specific Cloud.ru secret and Russian PII types are intentionally preserved as string entity types instead of being collapsed into a generic PII category.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:5002` | HTTP listen address |
| `RULE_FILES` | bundled Cloud.ru base + generated Gitleaks rules | Comma-separated YAML rule files |
| `KEYWORD_PREFILTER` | `true` | Enable Cloud.ru keyword prefilter |
| `INCLUDE_DEFAULT_OFF` | `false` | Include upstream rules marked `default_on: false` |
| `MAX_BODY_BYTES` | `8388608` | Maximum HTTP request body |

## Architecture

The adapter deliberately does **not** proxy LLM traffic. The Docker build overlays `cmd/presidio-adapter` into the pinned upstream Go module, so scanner behavior, overlap resolution, validators, and rule compilation come from the original project rather than a rewritten copy.

## License and provenance

This repository is Apache-2.0 licensed. It is a derived integration project based on [`cloud-ru-tech/guardrails-llm-filter`](https://github.com/cloud-ru-tech/guardrails-llm-filter), which is also Apache-2.0 licensed.

See [`NOTICE`](NOTICE). The container image additionally contains the upstream `LICENSE` and `NOTICE` as `/app/UPSTREAM-LICENSE` and `/app/UPSTREAM-NOTICE`.
