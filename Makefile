.PHONY: all build proto test lint clean docker-sim docker-down

PROJECT := github.com/had-nu/prana-provenance-chain
BUILD_DIR := bin

all: proto build

build:
	go build -o $(BUILD_DIR)/provenanced ./cmd/provenanced
	go build -o $(BUILD_DIR)/provectl ./cmd/provectl
	go build -o $(BUILD_DIR)/pipeline-sim ./cmd/pipeline-sim

proto:
	protoc --go_out=. --go_opt=module=$(PROJECT) \
		--go-grpc_out=. --go-grpc_opt=module=$(PROJECT) \
		pkg/server/api.proto

test:
	go test ./pkg/... -v -count=1

test-race:
	go test ./pkg/... -race -count=1

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)/
	rm -f pkg/server/api.pb.go
	rm -f pkg/server/api_grpc.pb.go

docker-sim:
	docker compose -f docker-compose.yml -f docker-compose.sim.yml up -d --build

docker-down:
	docker compose -f docker-compose.yml -f docker-compose.sim.yml down

docker-logs:
	docker compose -f docker-compose.yml -f docker-compose.sim.yml logs -f

docker-ps:
	docker compose -f docker-compose.yml -f docker-compose.sim.yml ps
