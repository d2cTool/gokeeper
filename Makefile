MODULE := gokeeper
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X $(MODULE)/pkg/version.Version=$(VERSION) -X $(MODULE)/pkg/version.BuildDate=$(BUILD_DATE)
CLIENT_DIR := bin/clients

.PHONY: all tools proto templ clients client-linux server test cover tidy

all: proto templ clients server

tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/a-h/templ/cmd/templ@latest

proto:
	go run github.com/bufbuild/buf/cmd/buf@latest generate

templ:
	go run github.com/a-h/templ/cmd/templ@latest generate

clients:
	mkdir -p $(CLIENT_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(CLIENT_DIR)/gophkeeper-windows-amd64.exe ./cmd/client
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(CLIENT_DIR)/gophkeeper-linux-amd64 ./cmd/client
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(CLIENT_DIR)/gophkeeper-darwin-amd64 ./cmd/client
	printf '{\n  "version": "%s",\n  "build_date": "%s",\n  "binaries": [\n    {"platform":"windows","arch":"amd64","filename":"gophkeeper-windows-amd64.exe"},\n    {"platform":"linux","arch":"amd64","filename":"gophkeeper-linux-amd64"},\n    {"platform":"darwin","arch":"amd64","filename":"gophkeeper-darwin-amd64"}\n  ]\n}\n' "$(VERSION)" "$(BUILD_DATE)" > $(CLIENT_DIR)/manifest.json

client-linux:
	bash scripts/build-client-linux.sh

server:
	go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-server ./cmd/server

test:
	go test ./...

cover:
	go test ./internal/auth ./internal/clientcfg ./internal/config ./internal/cryptox \
		./internal/download ./internal/storage/sqlite ./internal/transport/grpcx \
		./internal/transport/httpx ./internal/vault ./pkg/version -coverprofile=coverage.out
	go tool cover -func=coverage.out

tidy:
	go mod tidy
