# syntax=docker/dockerfile:1.7
ARG UPSTREAM_REF=bbd6f27467a53ff3869b59449edf4209f85ae675

FROM alpine/git:2.47.2 AS upstream
ARG UPSTREAM_REF
RUN git clone https://github.com/cloud-ru-tech/guardrails-llm-filter.git /src \
 && cd /src \
 && git checkout "$UPSTREAM_REF" \
 && git remote remove origin

FROM golang:1.26-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY --from=upstream /src/ /src/
# Overlay this project's adapter into the original Go module so it can reuse
# the upstream engine directly, without reimplementing scanner/registry logic.
COPY cmd/presidio-adapter/ /src/cmd/presidio-adapter/
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/presidio-adapter ./cmd/presidio-adapter

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/presidio-adapter /app/presidio-adapter
COPY --from=upstream /src/configs/guardrails_regex_rules.yaml /app/configs/guardrails_regex_rules.yaml
COPY --from=upstream /src/configs/guardrails_regex_rules.gitleaks.generated.yaml /app/configs/guardrails_regex_rules.gitleaks.generated.yaml
COPY --from=upstream /src/LICENSE /app/UPSTREAM-LICENSE
COPY --from=upstream /src/NOTICE /app/UPSTREAM-NOTICE
ENV LISTEN_ADDR=:5002 \
    RULE_FILES=/app/configs/guardrails_regex_rules.yaml,/app/configs/guardrails_regex_rules.gitleaks.generated.yaml \
    KEYWORD_PREFILTER=true
EXPOSE 5002
USER nonroot:nonroot
ENTRYPOINT ["/app/presidio-adapter"]
