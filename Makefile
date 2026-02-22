.PHONY: build build-linux clean test run

BINARY := creddy
BIN_DIR := bin

# Local build (native arch)
build:
	go build -o $(BIN_DIR)/$(BINARY) .

# Cross-compile for Linux x86_64 (exe.dev machines)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY)-linux-amd64 .

clean:
	rm -rf $(BIN_DIR)/

test:
	go test ./...

run: build
	./$(BIN_DIR)/$(BINARY) server
