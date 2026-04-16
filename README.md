# newton-auth-golang

Backend-only Newton School authentication SDK for Go applications.

The first-class integration target is Go's standard `net/http` stack. The SDK owns:
- `/newton/login` to start the Newton login redirect flow
- `/newton/callback` to complete the callback flow

Protected application routes stay explicit. They return `401` or `403`; they do not redirect automatically.

## Installation

Install from a Git tag so consumers get an immutable version instead of a moving branch head.

```bash
go get github.com/Newton-School/newton-auth-golang@v0.1.0
```

In `go.mod`:

```go
require github.com/Newton-School/newton-auth-golang v0.1.0
```

For private repository usage, configure `GOPRIVATE` appropriately before running `go get`.

For local development:

```bash
pre-commit install
go test ./...
```

## Compatibility

- Go `>=1.22`
- Standard `net/http` / `http.ServeMux`

The SDK mirrors the Python SDK and the current `platform_auth` backend contract:
- callback assertion format `v1.<nonce>.<ciphertext>.<aad>`
- AES-GCM callback assertion decryption using `sha256(callback_secret)`
- signed state and session cookies using HMAC-SHA256 over base64url JSON payloads

## Usage

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/Newton-School/newton-auth-golang/newtonauth"
)

func main() {
	auth, err := newtonauth.New(newtonauth.Config{
		ClientID:       os.Getenv("NEWTON_AUTH_CLIENT_ID"),
		ClientSecret:   os.Getenv("NEWTON_AUTH_CLIENT_SECRET"),
		CallbackSecret: os.Getenv("NEWTON_AUTH_CALLBACK_SECRET"),
		NewtonAPIBase:  getenv("NEWTON_AUTH_BASE_URL", "https://auth.newtonschool.co/api/v1"),
		CallbackPath:   "/newton/callback",
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/newton/login", auth.LoginHandler())
	mux.Handle("/newton/callback", auth.CallbackHandler())
	mux.Handle("/protected", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := newtonauth.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"uid":        user.UID,
			"authorized": user.Authorized,
		})
	})))

	log.Fatal(http.ListenAndServe(":8080", mux))
}

func getenv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
```

To start login, the frontend should navigate the browser to:

```text
/newton/login?next=/protected
```

After successful callback, the SDK sets a signed `newton_session` cookie and redirects to the original `next` path.

## Authorization

The SDK handles authentication and Newton platform access verification. Application-level authorization remains application-owned.

Use the authenticated Newton `uid` from request context to scope your own data:

```go
user, _ := newtonauth.UserFromContext(r.Context())
agents := repo.ListAgentsByOwnerUID(r.Context(), user.UID)
```

## Callback URL Contract

The callback path is client-configurable, but it must exactly match the redirect URI registered for the Newton OAuth application in the backend. The backend validates `redirect_uri` strictly.

## Release Process

This repository uses semantic versioning and GitHub releases. See [RELEASING.md](./RELEASING.md).

## Development Hooks

Pre-commit hooks are configured in `.pre-commit-config.yaml` and run:
- `gofmt -w` for Go file formatting
- `go test ./...` for the full test suite
