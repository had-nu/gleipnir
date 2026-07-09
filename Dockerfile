FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /provenanced ./cmd/provenanced && \
    CGO_ENABLED=0 go build -o /provectl ./cmd/provectl && \
    CGO_ENABLED=0 go build -o /pipeline-sim ./cmd/pipeline-sim

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /provenanced /usr/local/bin/
COPY --from=builder /provectl /usr/local/bin/
COPY --from=builder /pipeline-sim /usr/local/bin/
EXPOSE 50051 9090
ENTRYPOINT ["provenanced"]
