.PHONY: build install clean deps

deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

build: deps
	@echo "Building NoSQLi..."
	go build -o bin/NoSQLi main.go

install: build
	@echo "Installing nosqli-scanner..."
	go install

clean:
	@echo "Cleaning up..."
	rm -rf bin/
	rm -f NoSQLi

test:
	@echo "Running tests..."
	go test ./...
