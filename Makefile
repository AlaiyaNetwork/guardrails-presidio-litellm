UPSTREAM_REF ?= bbd6f27467a53ff3869b59449edf4209f85ae675
IMAGE ?= guardrails-presidio-litellm:dev

.PHONY: build run smoke fmt
build:
	docker build --build-arg UPSTREAM_REF=$(UPSTREAM_REF) -t $(IMAGE) .

run: build
	docker run --rm -p 5002:5002 $(IMAGE)

smoke:
	./scripts/smoke-test.sh

fmt:
	gofmt -w cmd/presidio-adapter/*.go
