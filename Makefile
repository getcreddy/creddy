.PHONY: build clean test run

build:
	go build -o bin/creddy .

clean:
	rm -rf bin/

test:
	go test ./...

run: build
	./bin/creddy server
