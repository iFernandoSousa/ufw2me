# AGENTS.md - ufw2me Development Guide

## Project Overview

ufw2me is a web-based firewall rule manager for UFW (Uncomplicated Firewall). It consists of a Go backend that serves a static frontend (HTML/CSS/JS). The Go binary embeds the frontend using `//go:embed`.

## Build Commands

```bash
# Build the Go binary
go build -o ufw2me

# Run in development mode (uses mock UFW data)
UFW2ME_DEV=1 go run main.go

# Run in production mode (requires UFW installed)
go run main.go

# Format code
go fmt ./...

# Run linter
go vet ./...

# Run all checks
go build ./... && go vet ./... && go fmt ./...
```

## Running a Single Test

There are currently **no test files** in this project. To add tests, create `*_test.go` files and run:

```bash
# Run all tests
go test ./...

# Run specific test
go test -run TestName ./...

# Run with verbose output
go test -v ./...
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Get UFW status and network interfaces |
| GET | `/api/rules` | Get current firewall rules |
| POST | `/api/rules/save` | Save and apply firewall rules |
| GET | `/api/interfaces` | Get network interfaces |
| POST | `/api/ufw/toggle` | Enable or disable UFW |

All endpoints return JSON and support CORS.

## Code Style Guidelines

### Go (Backend)

- **Formatting**: Use `go fmt` - standard Go formatting
- **Imports**: Group imports (stdlib first, then external)
  ```go
  import (
      "embed"
      "encoding/json"
      "fmt"
      "io/fs"
      "log"
      "net/http"
      "os"
      "os/exec"
      "regexp"
      "strconv"
      "strings"
      "sync"
  )
  ```
- **Types**: Use PascalCase for types (e.g., `Rule`, `StatusResponse`)
- **Variables**: Use camelCase (e.g., `devMode`, `port`)
- **Constants**: Use PascalCase (e.g., `DefaultPort`)
- **Naming**: Descriptive, avoid abbreviations except for common ones (e.g., `IP`, `URL`)
- **Error Handling**: Check errors and return early; use `jsonError` helper for API errors
- **Concurrency**: Use `sync.Mutex` for thread-safe operations (see `mu` in main.go)
- **Logging**: Use `log.Printf` for structured logging
- **HTTP Handlers**: Follow the pattern `handleXxx(w http.ResponseWriter, r *http.Request)`
- **Middleware**: Wrap handlers with middleware like `corsMiddleware`
- **Go Version**: Minimum Go 1.22.0 (from go.mod)
- **JSON Tags**: Use json tags for all exported struct fields
- **Command Execution**: Use `exec.Command` with `CombinedOutput()` for UFW commands

### Frontend (HTML/CSS/JS)

- **No framework**: Vanilla JS, no build tools
- **Style**: CSS variables for theming (dark/light modes per spec)
- **JS**: ES6+ features (const/let, arrow functions, async/await)
- **No external dependencies** in frontend
- **API Calls**: Use `fetch()` with async/await patterns
- **State Management**: Simple in-memory state in JavaScript

### General Conventions

- **File Structure**: Single main.go in root, frontend in `/frontend` directory
- **Embedding**: Frontend is embedded using `//go:embed frontend/*`
- **API Design**: RESTful JSON APIs under `/api/*`
- **CORS**: Uses wildcard CORS middleware for development
- **Dev Mode**: Set `UFW2ME_DEV=1` for mock behavior (no actual UFW commands)
- **Port**: Default 9850, configurable via `UFW2ME_PORT` env var

## Key Files

- `main.go` - All backend logic (592 lines)
- `frontend/index.html` - Main HTML page
- `frontend/styles.css` - CSS styling
- `frontend/app.js` - Frontend JavaScript
- `spec/spec.md` - Technical specification

## Architecture Patterns

### Adding a New API Endpoint

1. Add route in `main()`: `mux.HandleFunc("/api/endpoint", corsMiddleware(handleEndpoint))`
2. Create handler function:
   ```go
   func handleEndpoint(w http.ResponseWriter, r *http.Request) {
       if r.Method != "GET" {
           jsonError(w, "Method not allowed", 405)
           return
       }
       // Business logic here
       jsonResponse(w, responseData)
   }
   ```

### UFW Command Execution

Always wrap UFW commands in `runUFW()` function which handles dev mode:
```go
func runUFW(args ...string) (string, error) {
    if devMode {
        return mockUFW(args...)
    }
    cmd := exec.Command("ufw", args...)
    out, err := cmd.CombinedOutput()
    return string(out), err
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UFW2ME_PORT` | 9850 | HTTP server port |
| `UFW2ME_DEV` | (empty) | Set to "1" for mock mode |

## Common Issues

- **UFW not installed**: Production mode requires UFW installed on the system
- **Permission denied**: UFW commands require root privileges
- **Port already in use**: Change port via `UFW2ME_PORT` environment variable
- **Mock data**: Use dev mode for testing without requiring UFW