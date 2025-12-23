<div align = "center">
  <img alt = "project logo" src = "https://github.com/OliveTin/OliveTin/blob/main/frontend/OliveTinLogo.png" width = "128" />
  <h1>httpauthshim</h1>

  The glue code for HTTP authentication in Go.

  [![Maturity Shield](https://img.shields.io/badge/maturity-alpha-red.svg)](https://github.com/jamesread/httpauthshim)
  [![Discord](https://img.shields.io/discord/846737624960860180?label=Discord%20Server)](https://discord.gg/jhYWWpNJ3v)
</div>

A Go library for HTTP request authentication that supports multiple authentication methods including JWT, OAuth2, local sessions, and trusted headers.

## Features

- **Multiple Authentication Methods**: Supports JWT (header/cookie), OAuth2, local password-based sessions, and trusted HTTP headers
- **Extensible Auth Chain**: Easily add custom authentication handlers
- **Session Management**: Persistent session storage with YAML-based backend
- **Access Control Lists**: Configurable ACLs based on username and usergroup matching
- **OAuth2 Providers**: Built-in support for GitHub and Google, with extensible provider system
- **Security**: Argon2id password hashing, timing attack prevention, secure session handling

## Installation

```bash
go get github.com/jamesread/httpauthshim
```

## Quick Start

```go
package main

import (
    "net/http"
    
    "github.com/jamesread/httpauthshim"  // Imports the 'auth' package
    "github.com/jamesread/httpauthshim/authpublic"
)

func handler(w http.ResponseWriter, r *http.Request) {
    cfg := &authpublic.Config{
        // Configure your authentication methods
    }
    
    // Create an AuthShimContext - this is the main entry point
    ctx, err := auth.NewAuthShimContext(cfg)
    if err != nil {
        http.Error(w, "Failed to initialize auth", http.StatusInternalServerError)
        return
    }
    
    // Authenticate the user
    user := ctx.AuthFromHttpReq(r)
    
    if user.IsGuest() {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    // User is authenticated, proceed with request
    w.Write([]byte("Hello, " + user.Username))
}
```

## Authentication Methods

### JWT Authentication

Supports JWT tokens from:
- HTTP headers (configurable header name, defaults to `Authorization` with `Bearer` prefix)
- HTTP cookies (configurable cookie name)

Supports multiple verification methods:
- Remote JWKS (JSON Web Key Set) URL
- Local RSA public key file
- HMAC secret

### OAuth2 Authentication

Built-in support for GitHub and Google OAuth2 providers. Easily extensible for other providers.

```go
import "github.com/jamesread/httpauthshim/providers/hasoauth2"

// Create AuthShimContext first
ctx, err := auth.NewAuthShimContext(cfg)
if err != nil {
    // Handle error
}

// Pass session storage from AuthShimContext for instance-based storage
handler := hasoauth2.NewOAuth2Handler(cfg, ctx.Sessions)
http.HandleFunc("/oauth/login", handler.HandleOAuthLogin)
http.HandleFunc("/oauth/callback", handler.HandleOAuthCallback)

// Add OAuth2 to auth chain using the context instance
ctx.AddProvider(handler.CheckUserFromOAuth2Cookie)
```

### Local Password Authentication

Password-based authentication with Argon2id hashing:

```go
import "github.com/jamesread/httpauthshim/providers/haslocal"

// Create password hash
hash, err := haslocal.CreateHash("userpassword")

// Verify password
isValid := haslocal.CheckUserPassword(cfg, "username", "password")
```

### Trusted HTTP Headers

Authenticate users based on trusted HTTP headers (useful for reverse proxy setups):

```yaml
httpHeader:
  username: "X-Username"
  userGroup: "X-User-Group"
  userGroupSep: ","
```

### mTLS (Mutual TLS) Authentication

Authenticate users based on client certificates in TLS connections:

```go
import "github.com/jamesread/httpauthshim/providers/hasmtls"

cfg := &authpublic.Config{
    Mtls: authpublic.MtlsConfig{
        Enabled: true,
        UsernameFromCN: true,        // Extract username from Common Name
        GroupFromOU: true,           // Extract groups from Organizational Unit
        // Or use SAN fields:
        // UsernameFromSANEmail: true,
        // GroupFromSANDNS: true,
    },
}

ctx, _ := auth.NewAuthShimContext(cfg)
ctx.AddProvider(hasmtls.CheckUserFromMtls)
```

Configuration options (under `mtls` key):
- `enabled`: Enable mTLS authentication
- `requireClientCert`: Require client certificate (default: false)
- `usernameFromCN`: Extract username from Common Name
- `usernameFromSANEmail`: Extract username from SAN email addresses
- `usernameStripEmailDomain`: Strip domain from email addresses
- `usernameOID`: Extract username from custom OID (e.g., "1.2.840.113549.1.9.1")
- `groupFromOU`: Extract groups from Organizational Unit fields
- `groupFromSANEmail`: Extract groups from SAN email addresses
- `groupFromSANDNS`: Extract groups from SAN DNS names
- `groupSANPrefix`: Filter SAN DNS names by prefix
- `groupOID`: Extract groups from custom OID
- `groupSeparator`: Separator for multiple groups in OID value

## Configuration

The library uses a YAML-based configuration structure. See `authpublic.Config` for all available options.

Example configuration:

```yaml
jwt:
  header: "Authorization"
  claimUsername: "sub"
  claimUserGroup: "groups"

localUsers:
  enabled: true
  users:
    - username: "admin"
      usergroup: "admin"
      password: "$argon2id$v=19$m=65536,t=4,p=1$..."

oauth2Providers:
  github:
    clientId: "your-client-id"
    clientSecret: "your-client-secret"
    redirectUrl: "https://yourapp.com/oauth/callback"

accessControlLists:
  - name: "admin"
    matchUsernames: ["admin"]
    matchUsergroups: ["admin"]
```

## Package Structure

- `auth` - Main authentication package with auth chain and core functions
- `authpublic` - Public types and configuration structures
- `sessions` - Session management and storage
- `providers/hasjwt` - JWT token parsing and validation
- `providers/hasoauth2` - OAuth2 authentication handlers
- `providers/haslocal` - Local password-based authentication and sessions
- `providers/hasmtls` - Mutual TLS (mTLS) client certificate authentication
- `providers/hastrustedheaders` - Trusted HTTP headers authentication

## Extending the Auth Chain

Add custom authentication handlers to your `AuthShimContext`:

```go
// Create AuthShimContext first
ctx, err := auth.NewAuthShimContext(cfg)
if err != nil {
    // Handle error
}

// Add custom provider to the context's auth chain
ctx.AddProvider(func(authCtx *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
    // Your custom authentication logic
    // Return nil or empty user if authentication fails
    // Return AuthenticatedUser if successful
})
```

**Note**: The deprecated global `auth.AddProvider()` function modifies a shared global chain and should be avoided. Always use `ctx.AddProvider()` for per-context provider chains.

## Session Management

Sessions are persisted to disk in YAML format. By default, sessions are stored in `~/.config/auth/sessions.yaml`, but this can be configured via the `BaseDir` field in the config or the `AUTH_HOME` environment variable.

When using `AuthShimContext`, sessions are automatically loaded on creation and managed through the context:

```go
// Create context (sessions are automatically loaded)
ctx, err := auth.NewAuthShimContext(cfg)
if err != nil {
    // Handle error
}

// Register a session
ctx.RegisterUserSession("provider", "session-id", "username", "usergroup")

// Retrieve a session
session := ctx.GetUserSession("provider", "session-id")

// Delete a session
ctx.DeleteUserSession("provider", "session-id")
```

### Backward Compatibility (Deprecated)

**⚠️ DEPRECATED**: The following functions use global session storage and are deprecated. Use `AuthShimContext` methods instead for instance-based storage.

```go
import "github.com/jamesread/httpauthshim/sessions"

// Register a session (uses global storage - DEPRECATED)
sessions.RegisterUserSession(cfg, "provider", "session-id", "username", "usergroup")

// Retrieve a session (uses global storage - DEPRECATED)
session := sessions.GetUserSession("provider", "session-id")

// Delete a session (uses global storage - DEPRECATED)
sessions.DeleteUserSession(cfg, "provider", "session-id")

// Load sessions from disk (call on startup - DEPRECATED)
sessions.LoadUserSessions(cfg)
```

**Migration**: Replace these with `ctx.RegisterUserSession()`, `ctx.GetUserSession()`, `ctx.DeleteUserSession()` methods on your `AuthShimContext` instance.


## Contributing

Please checkout CONTRIBUTING.md.
