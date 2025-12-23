# Agent Instructions

This document contains instructions for AI agents working on this codebase.

## Code Quality Requirements

### Cyclomatic Complexity

All functions in the library code must have a cyclomatic complexity of 5 or less. The `make gocyclo` command enforces this requirement.

**To check:**
```bash
make gocyclo
```

**To fix:**
- Refactor complex functions by extracting helper functions
- Break down large functions into smaller, focused functions
- Reduce nested conditionals and loops
- Use early returns to reduce nesting

**Note:** Functions in `examples/` are excluded from this requirement, but library code must comply. The `make gocyclo` command automatically excludes example files.

### Linter Compliance

All code must pass `golangci-lint` checks:

```bash
make golangci
```

Or directly:
```bash
golangci-lint run
```

**To fix issues:**
- Address all reported linter errors
- Use `//nolint` comments sparingly and only when necessary
- Clear the linter cache if needed: `golangci-lint cache clean`

## Testing

Run tests with:
```bash
make test
```

Or directly:
```bash
go test -v ./...
```

## Building

Build the project with:
```bash
make build
```

Or directly:
```bash
go build ./...
```
