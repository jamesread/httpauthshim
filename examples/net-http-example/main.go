package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jamesread/httpauthshim"
	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/jamesread/httpauthshim/providers/haslocal"
	"github.com/jamesread/httpauthshim/providers/hasmtls"
	"github.com/jamesread/httpauthshim/providers/hasoauth2"
)

func main() {
	// Create authentication configuration
	cfg := &authpublic.Config{
		// Trusted headers authentication
		HttpHeader: authpublic.HttpHeaderConfig{
			Username:     "X-Username",
			UserGroup:    "X-User-Group",
			UserGroupSep: ",",
		},

		// JWT authentication
		Jwt: authpublic.JwtConfig{
			Header:        "Authorization",
			ClaimUsername: "sub",
			ClaimUserGroup: "groups",
			CookieName:    "auth-token",
		},

		// Local users configuration
		LocalUsers: authpublic.LocalUsersConfig{
			Enabled: true,
			Users: []*authpublic.LocalUser{
				{
					Username:  "admin",
					Usergroup: "admin",
					// Password: "admin123" - In production, use haslocal.CreateHash() to generate hash
					Password: "$argon2id$v=19$m=65536,t=4,p=4$dGVzdHNhbHQ$testhash",
				},
			},
		},

		// OAuth2 providers (optional)
		OAuth2Providers: map[string]*authpublic.OAuth2Provider{
			"github": {
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			},
		},
		OAuth2RedirectURL: "http://localhost:8080/oauth/callback",

		// mTLS (Mutual TLS) configuration
		Mtls: authpublic.MtlsConfig{
			Enabled:             true,
			RequireClientCert:    false, // Set to true to require client certs
			UsernameFromCN:       true,  // Extract username from Common Name
			UsernameFromSANEmail: false, // Or extract from SAN email
			GroupFromOU:          true,  // Extract groups from Organizational Unit
			GroupFromSANDNS:      false, // Or extract from SAN DNS names
		},

		// Access Control Lists
		AccessControlLists: []authpublic.AccessControlList{
			{
				Name:           "admin",
				MatchUsernames: []string{"admin"},
				MatchUsergroups: []string{"admin"},
			},
		},
	}

	// Create AuthShimContext - this is the main entry point
	authCtx, err := auth.NewAuthShimContext(cfg)
	if err != nil {
		log.Fatalf("Failed to create auth context: %v", err)
	}

	// Add mTLS to auth chain if enabled
	if cfg.Mtls.Enabled {
		authCtx.AddProvider(hasmtls.CheckUserFromMtls)
	}

	// Set up OAuth2 handler if configured
	var oauth2Handler *hasoauth2.OAuth2Handler
	if len(cfg.OAuth2Providers) > 0 {
		oauth2Handler = hasoauth2.NewOAuth2Handler(cfg, authCtx.Sessions)
		// Add OAuth2 to auth chain
		authCtx.AddProvider(oauth2Handler.CheckUserFromOAuth2Cookie)

		// Set up OAuth2 routes
		http.HandleFunc("/oauth/login", oauth2Handler.HandleOAuthLogin)
		http.HandleFunc("/oauth/callback", oauth2Handler.HandleOAuthCallback)
	}

	// Protected route - requires authentication
	http.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate the user
		user := authCtx.AuthFromHttpReq(r)

		if user.IsGuest() {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// User is authenticated, proceed with request
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"message": "Hello, %s!",
			"username": "%s",
			"usergroup": "%s",
			"provider": "%s",
			"acls": %v
		}`, user.Username, user.Username, user.UsergroupLine, user.Provider, user.Acls)
	})

	// Admin-only route
	http.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
		user := authCtx.AuthFromHttpReq(r)

		if user.IsGuest() {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if user has admin ACL
		hasAdminACL := false
		for _, acl := range user.Acls {
			if acl == "admin" {
				hasAdminACL = true
				break
			}
		}

		if !hasAdminACL {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"message": "Admin access granted",
			"username": "%s"
		}`, user.Username)
	})

	// Login endpoint (for local password authentication)
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			http.Error(w, "Username and password required", http.StatusBadRequest)
			return
		}

		// Check password
		if !haslocal.CheckUserPassword(cfg, username, password) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Generate session ID (in production, use crypto/rand)
		sessionID := fmt.Sprintf("session-%s", username)

		// Register session
		authCtx.RegisterUserSession("local", sessionID, username, "")

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.GetLocalSessionCookieName(),
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
		})

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"message": "Login successful",
			"session_id": "%s"
		}`, sessionID)
	})

	// Public route - no authentication required
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := authCtx.AuthFromHttpReq(r)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<title>HTTP Auth Shim Example</title>
</head>
<body>
	<h1>HTTP Auth Shim Example</h1>
	<p>Current user: <strong>%s</strong></p>
	<p>Provider: %s</p>
	<p>User Group: %s</p>
	
	<h2>Endpoints:</h2>
	<ul>
		<li><a href="/api/protected">Protected API</a> - Requires authentication</li>
		<li><a href="/api/admin">Admin API</a> - Requires admin ACL</li>
		<li><a href="/api/login">Login</a> - POST with username/password</li>
	`, user.Username, user.Provider, user.UsergroupLine)

		if oauth2Handler != nil {
			fmt.Fprintf(w, `		<li><a href="/oauth/login?provider=github">OAuth2 Login (GitHub)</a></li>
`)
		}

		fmt.Fprintf(w, `	</ul>
</body>
</html>`)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: nil,
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		log.Printf("Starting server on :%s", port)
		log.Printf("Visit http://localhost:%s to see the example", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down gracefully...")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down server: %v", err)
	}

	// Shutdown OAuth2 handler if it exists
	if oauth2Handler != nil {
		oauth2Handler.Shutdown()
	}

	// Shutdown auth context
	if err := authCtx.Shutdown(); err != nil {
		log.Printf("Error shutting down auth context: %v", err)
	}

	log.Println("Shutdown complete")
}
