package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/jamesread/httpauthshim/sessions"
	log "github.com/sirupsen/logrus"
)

// AuthShimContext contains the configuration and session storage for authentication.
// This is the main entry point for users of the library.
//
// IMPORTANT: The Config should not be mutated after AuthShimContext creation.
// Mutating the config after context creation can lead to inconsistent behavior
// and is not thread-safe. If you need to change configuration, create a new
// AuthShimContext with the updated config.
//
// CLEANUP: You MUST call Shutdown() when the AuthShimContext is no longer needed
// to prevent resource leaks (goroutines, file handles, etc.). This is especially
// important in long-running applications. Consider using defer or ensuring Shutdown
// is called in your application's cleanup logic (e.g., signal handlers).
type AuthShimContext struct {
	Config       *authpublic.Config
	Sessions     *sessions.SessionStorage
	chain        []func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser
	chainMu      sync.RWMutex
	shutdownOnce sync.Once // Ensures shutdown is only called once
}

// NewAuthShimContext creates a new AuthShimContext with the provided config and session storage.
// It loads existing sessions from disk.
// It validates the configuration and returns an error if validation fails.
// Callers must explicitly provide a SessionStorage implementation.
func NewAuthShimContext(cfg *authpublic.Config, sessionStorage *sessions.SessionStorage) (*AuthShimContext, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	if sessionStorage == nil {
		return nil, fmt.Errorf("sessionStorage cannot be nil; callers must explicitly provide a SessionStorage implementation")
	}

	ctx := &AuthShimContext{
		Config:   cfg,
		Sessions: sessionStorage,
		chain:    make([]func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser, 0),
	}

	// Load existing sessions from disk
	if err := ctx.Sessions.Load(cfg.GetDir(), cfg.GetSessionFileName()); err != nil {
		// Non-fatal error, sessions will start empty
		log.WithError(err).Debug("Failed to load sessions, starting with empty storage")
	}

	return ctx, nil
}

// AuthFromHttpReq authenticates a user from an HTTP request.
// It runs through the authentication chain and returns an AuthenticatedUser.
// If no user is authenticated, it returns a guest user.
// For error handling, use AuthFromHttpReqWithError instead.
func (ctx *AuthShimContext) AuthFromHttpReq(req *http.Request) *authpublic.AuthenticatedUser {
	user, _ := ctx.AuthFromHttpReqWithError(req)
	return user
}

// AuthFromHttpReqWithError authenticates a user from an HTTP request.
// It runs through the authentication chain and returns an AuthenticatedUser and any error encountered.
// If no user is authenticated, it returns a guest user and nil error.
func (ctx *AuthShimContext) AuthFromHttpReqWithError(req *http.Request) (*authpublic.AuthenticatedUser, error) {
	user, err := ctx.runAuthChain(req)

	if err != nil {
		return ctx.UserGuest(), err
	}

	if user == nil || user.Username == "" {
		user = ctx.UserGuest()
	} else {
		user.BuildUserAcls(ctx.Config)
	}

	path := ""
	if req != nil {
		path = req.URL.Path
	}

	log.WithFields(log.Fields{
		"username":      user.Username,
		"usergroupLine": user.UsergroupLine,
		"provider":      user.Provider,
		"acls":          user.Acls,
		"path":          path,
	}).Debugf("Authenticated API request")

	return user, nil
}

// sendResultNonBlocking sends a result to the channel without blocking if receiver moved on
func sendResultNonBlocking(resultChan chan<- *authpublic.AuthenticatedUser, result *authpublic.AuthenticatedUser, providerCtx context.Context) {
	select {
	case resultChan <- result:
		// Result sent successfully
	case <-providerCtx.Done():
		// Context cancelled, receiver already moved on - exit immediately
	}
}

// handleProviderPanic recovers from panics in provider functions and sends nil result
func handleProviderPanic(req *http.Request, providerCtx context.Context, resultChan chan<- *authpublic.AuthenticatedUser) {
	if r := recover(); r != nil {
		log.WithFields(log.Fields{
			"panic": r,
			"path":  getRequestPath(req),
		}).Errorf("Panic recovered in authentication provider")
		sendResultNonBlocking(resultChan, nil, providerCtx)
	}
}

// runProviderInGoroutine runs a single provider function in a goroutine with timeout protection
func runProviderInGoroutine(
	check func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser,
	authCtx *authpublic.AuthCheckingContext,
	providerCtx context.Context,
	req *http.Request,
	resultChan chan<- *authpublic.AuthenticatedUser,
) {
	defer handleProviderPanic(req, providerCtx, resultChan)

	// Check if context is already cancelled before starting work
	if providerCtx.Err() != nil {
		sendResultNonBlocking(resultChan, nil, providerCtx)
		return
	}

	// Create auth context with timeout context
	timeoutAuthCtx := &authpublic.AuthCheckingContext{
		Request:  authCtx.Request,
		Config:   authCtx.Config,
		Sessions: authCtx.Sessions,
		Context:  providerCtx,
	}

	// Call provider - it should respect the context passed in timeoutAuthCtx.Context
	// If provider doesn't respect context, it may run longer than timeout, but
	// our goroutine will exit promptly after sending result (non-blocking send)
	result := check(timeoutAuthCtx)
	sendResultNonBlocking(resultChan, result, providerCtx)
}

// getRequestPath extracts the path from a request for logging purposes
func getRequestPath(req *http.Request) string {
	if req != nil && req.URL != nil {
		return req.URL.Path
	}
	return ""
}

// executeProviderWithTimeout executes a single provider with timeout protection
func executeProviderWithTimeout(
	check func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser,
	authCtx *authpublic.AuthCheckingContext,
	reqCtx context.Context,
	req *http.Request,
	timeout time.Duration,
) (*authpublic.AuthenticatedUser, error) {
	// Check if context has been cancelled before calling provider
	if err := reqCtx.Err(); err != nil {
		return nil, fmt.Errorf("request context cancelled: %w", err)
	}

	// Create timeout context for this provider call
	providerCtx, cancel := context.WithTimeout(reqCtx, timeout)
	defer cancel()

	resultChan := make(chan *authpublic.AuthenticatedUser, 1)
	go runProviderInGoroutine(check, authCtx, providerCtx, req, resultChan)

	// Wait for provider result or timeout
	select {
	case <-providerCtx.Done():
		if providerCtx.Err() == context.DeadlineExceeded {
			log.WithFields(log.Fields{
				"timeout": timeout,
				"path":    getRequestPath(req),
			}).Warnf("Authentication provider exceeded timeout, skipping")
			return nil, nil
		}
		return nil, fmt.Errorf("request context cancelled: %w", providerCtx.Err())
	case result := <-resultChan:
		return result, nil
	}
}

// runAuthChain runs through all authentication providers in order
func (ctx *AuthShimContext) runAuthChain(req *http.Request) (*authpublic.AuthenticatedUser, error) {
	// Extract context from request, or use background context if request is nil
	reqCtx := context.Background()
	if req != nil {
		reqCtx = req.Context()
	}

	authCtx := &authpublic.AuthCheckingContext{
		Request:  req,
		Config:   ctx.Config,
		Sessions: ctx.Sessions,
		Context:  reqCtx,
	}

	ctx.chainMu.RLock()
	chain := make([]func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser, len(ctx.chain))
	copy(chain, ctx.chain)
	ctx.chainMu.RUnlock()

	// Default provider timeout (30 seconds)
	providerTimeout := 30 * time.Second

	return executeAuthChain(chain, authCtx, reqCtx, req, providerTimeout)
}

// checkProviderResult checks if a provider result is valid and returns it
func checkProviderResult(result *authpublic.AuthenticatedUser, reqCtx context.Context) (*authpublic.AuthenticatedUser, error) {
	if err := reqCtx.Err(); err != nil {
		return nil, fmt.Errorf("request context cancelled: %w", err)
	}
	if result != nil && result.Username != "" {
		return result, nil
	}
	return nil, nil
}

// executeAuthChain executes the authentication chain
func executeAuthChain(
	chain []func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser,
	authCtx *authpublic.AuthCheckingContext,
	reqCtx context.Context,
	req *http.Request,
	providerTimeout time.Duration,
) (*authpublic.AuthenticatedUser, error) {
	for _, check := range chain {
		result, err := executeProviderWithTimeout(check, authCtx, reqCtx, req, providerTimeout)
		if err != nil {
			return nil, err
		}

		if finalResult, err := checkProviderResult(result, reqCtx); err != nil || finalResult != nil {
			return finalResult, err
		}
	}

	return nil, nil
}

// RegisterUserSession registers a new user session
func (ctx *AuthShimContext) RegisterUserSession(provider string, sid string, username string, usergroup ...string) {
	ctx.Sessions.RegisterSession(ctx.Config.GetDir(), ctx.Config.GetSessionFileName(), provider, sid, username, usergroup...)
}

// GetUserSession retrieves a user session
func (ctx *AuthShimContext) GetUserSession(provider string, sid string) *sessions.UserSession {
	return ctx.Sessions.GetSession(provider, sid)
}

// DeleteUserSession deletes a user session
func (ctx *AuthShimContext) DeleteUserSession(provider string, sid string) {
	ctx.Sessions.DeleteSession(ctx.Config.GetDir(), ctx.Config.GetSessionFileName(), provider, sid)
}

// UserGuest returns a guest user with appropriate ACLs
func (ctx *AuthShimContext) UserGuest() *authpublic.AuthenticatedUser {
	return UserGuest(ctx.Config)
}

// UserFromSystem returns a system user with the given username
func (ctx *AuthShimContext) UserFromSystem(username string) *authpublic.AuthenticatedUser {
	return UserFromSystem(ctx.Config, username)
}

// AddProvider adds a custom authentication provider to this context's auth chain.
// This allows users to extend the authentication chain with custom providers.
// The provider is added to this specific context instance, not a global chain.
func (ctx *AuthShimContext) AddProvider(check func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser) {
	ctx.chainMu.Lock()
	defer ctx.chainMu.Unlock()
	ctx.chain = append(ctx.chain, check)
}

// RemoveProviderByIndex removes a provider from the auth chain by index.
// Returns an error if the index is out of bounds.
func (ctx *AuthShimContext) RemoveProviderByIndex(index int) error {
	ctx.chainMu.Lock()
	defer ctx.chainMu.Unlock()

	if index < 0 || index >= len(ctx.chain) {
		return fmt.Errorf("provider index %d out of bounds (chain length: %d)", index, len(ctx.chain))
	}

	ctx.chain = append(ctx.chain[:index], ctx.chain[index+1:]...)
	return nil
}

// ClearProviders removes all providers from the auth chain.
func (ctx *AuthShimContext) ClearProviders() {
	ctx.chainMu.Lock()
	defer ctx.chainMu.Unlock()
	ctx.chain = make([]func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser, 0)
}

// InsertProvider inserts a provider at a specific index in the auth chain.
// If index is out of bounds, the provider is appended to the end.
func (ctx *AuthShimContext) InsertProvider(index int, check func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser) {
	ctx.chainMu.Lock()
	defer ctx.chainMu.Unlock()

	if index < 0 || index >= len(ctx.chain) {
		ctx.chain = append(ctx.chain, check)
		return
	}

	ctx.chain = append(ctx.chain[:index], append([]func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser{check}, ctx.chain[index:]...)...)
}

// GetProviders returns a copy of the current provider chain.
// Useful for debugging or inspection.
func (ctx *AuthShimContext) GetProviders() []func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	ctx.chainMu.RLock()
	defer ctx.chainMu.RUnlock()

	chain := make([]func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser, len(ctx.chain))
	copy(chain, ctx.chain)
	return chain
}

// Shutdown performs cleanup operations, including:
// - Final session storage write
// - Stopping background goroutines
// This MUST be called when the context is no longer needed to prevent resource leaks.
// It is safe to call Shutdown multiple times; subsequent calls are no-ops.
func (ctx *AuthShimContext) Shutdown() error {
	var err error
	ctx.shutdownOnce.Do(func() {
		err = ctx.Sessions.Shutdown(ctx.Config.GetDir(), ctx.Config.GetSessionFileName())
	})
	return err
}

// validateJwtConfig validates JWT configuration
func validateJwtConfig(cfg *authpublic.Config) error {
	if cfg.Jwt.CertsURL != "" && cfg.Jwt.PubKeyPath != "" {
		return fmt.Errorf("JWT configuration error: cannot specify both certsURL and pubKeyPath")
	}
	return nil
}

// validateMtlsConfig validates mTLS configuration
func validateMtlsConfig(cfg *authpublic.Config) error {
	if !cfg.Mtls.Enabled {
		return nil
	}
	if !cfg.Mtls.UsernameFromCN && !cfg.Mtls.UsernameFromSANEmail && cfg.Mtls.UsernameOID == "" {
		return fmt.Errorf("mTLS configuration error: must specify at least one username extraction method")
	}
	return nil
}

// validateOAuth2Config validates OAuth2 configuration
func validateOAuth2Config(cfg *authpublic.Config) error {
	if len(cfg.OAuth2Providers) > 0 && cfg.OAuth2RedirectURL == "" {
		return fmt.Errorf("OAuth2 configuration error: oauth2RedirectUrl is required when oauth2Providers are configured")
	}
	return nil
}

// validateConfig validates the configuration for consistency and required fields.
func validateConfig(cfg *authpublic.Config) error {
	if err := validateJwtConfig(cfg); err != nil {
		return err
	}
	if err := validateMtlsConfig(cfg); err != nil {
		return err
	}
	return validateOAuth2Config(cfg)
}
