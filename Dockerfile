# 1.27, not 1.24: go.mod requires `go 1.27`, and crypto/mldsa (the ML-DSA-65
# wrapper this project is built on) is only in the standard library from 1.24
# onwards. The previous 1.24 pin meant `go mod download` failed under
# GOTOOLCHAIN=local and no image ever built.
#
# Kept in step with GO_VERSION in .github/workflows/ci.yml. The two drifting
# apart is what let the mismatch go unnoticed: CI passed because it installs its
# own toolchain, and the Dockerfile was only exercised by `docker compose build`.
FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /provenanced ./cmd/provenanced && \
    CGO_ENABLED=0 go build -o /provectl ./cmd/provectl && \
    CGO_ENABLED=0 go build -o /pipeline-sim ./cmd/pipeline-sim && \
    CGO_ENABLED=0 go build -o /conformance-test ./cmd/conformance-test

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=builder /provenanced /usr/local/bin/
COPY --from=builder /provectl /usr/local/bin/
COPY --from=builder /pipeline-sim /usr/local/bin/
COPY --from=builder /conformance-test /usr/local/bin/
EXPOSE 50051 9090
ENTRYPOINT ["provenanced"]
