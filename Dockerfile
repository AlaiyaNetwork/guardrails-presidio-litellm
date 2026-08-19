# syntax=docker/dockerfile:1.7
ARG UPSTREAM_REF=bbd6f27467a53ff3869b59449edf4209f85ae675

# Keep a pinned upstream checkout for the bundled rules and license provenance.
FROM alpine/git:2.47.2 AS upstream
ARG UPSTREAM_REF
RUN git clone https://github.com/cloud-ru-tech/guardrails-llm-filter.git /upstream \
 && cd /upstream \
 && git checkout "$UPSTREAM_REF" \
 && git remote remove origin

# Build this repository as its own module. The Cloud.ru engine is a pinned Go
# module dependency in go.mod; we no longer overlay our command into upstream.
FROM golang:1.26.5-alpine AS build
RUN apk add --no-cache ca-certificates git
WORKDIR /src
COPY go.mod ./
COPY cmd/presidio-adapter/ ./cmd/presidio-adapter/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod tidy \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/presidio-adapter ./cmd/presidio-adapter

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/presidio-adapter /app/presidio-adapter
COPY --from=upstream /upstream/configs/guardrails_regex_rules.yaml /app/configs/guardrails_regex_rules.yaml
COPY --from=upstream /upstream/configs/guardrails_regex_rules.gitleaks.generated.yaml /app/configs/guardrails_regex_rules.gitleaks.generated.yaml
COPY --from=upstream /upstream/LICENSE /app/UPSTREAM-LICENSE
COPY --from=upstream /upstream/NOTICE /app/UPSTREAM-NOTICE
ENV LISTEN_ADDR=:5002 \
    RULE_FILES=/app/configs/guardrails_regex_rules.yaml,/app/configs/guardrails_regex_rules.gitleaks.generated.yaml \
    KEYWORD_PREFILTER=true \
    INCLUDE_DEFAULT_OFF=true
EXPOSE 5002
USER nonroot:nonroot
ENTRYPOINT ["/app/presidio-adapter"]
