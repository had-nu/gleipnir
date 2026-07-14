.PHONY: all build proto test lint clean docker-sim docker-down

# IPC (Immutable Provenance Chain) — Gleipnir reference implementation
PROJECT := github.com/had-nu/gleipnir
BUILD_DIR := bin

all: proto build

build:
	go build -o $(BUILD_DIR)/provenanced ./cmd/provenanced
	go build -o $(BUILD_DIR)/provectl ./cmd/provectl
	go build -o $(BUILD_DIR)/pipeline-sim ./cmd/pipeline-sim
	go build -o $(BUILD_DIR)/cube-room ./frontend-test/cube-room

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

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-sim:
	docker compose -f docker-compose.yml -f docker-compose.sim.yml --profile sim up -d --build

docker-logs:
	docker compose logs -f

docker-ps:
	docker compose ps

docker-conformance:
	docker compose -f docker-compose.yml -f docker-compose.test.yml up --detach --build
	@echo "Waiting for validators..."
	@for i in $$(seq 1 30); do \
		if docker compose -f docker-compose.yml -f docker-compose.test.yml logs val-1 2>/dev/null | grep -q "listening"; then \
			break; \
		fi; \
		sleep 1; \
	done
	@echo "Running conformance test..."
	docker compose -f docker-compose.yml -f docker-compose.test.yml run --build --rm conformance-test; \
	EXIT_CODE=$$?; \
	docker compose -f docker-compose.yml -f docker-compose.test.yml down -v; \
	exit $$EXIT_CODE

docker-conformance-clean:
	docker compose -f docker-compose.yml -f docker-compose.test.yml --profile test down -v
