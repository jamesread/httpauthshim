.PHONY: build test gocyclo clean

build:
	@echo "Building httpauthshim..."
	@go build ./...

test:
	@echo "Running unit tests..."
	@go test -v ./...

gocyclo:
	@echo "Running gocyclo..."
	@if gocyclo -over 5 . | grep -v "examples/" | grep -qE "^[0-9]+"; then \
		gocyclo -over 5 . | grep -v "examples/"; \
		echo "Error: Functions with complexity > 5 found in library code"; \
		exit 1; \
	fi
	@echo "All library functions have complexity <= 5"

clean:
	@echo "Cleaning build artifacts..."
	@go clean ./...

golangci:
	golangci-lint run
