package auth

import (
	"context"
	"net/http"
	"sync"

	types "github.com/jamesread/httpauthshim/authpublic"
	log "github.com/sirupsen/logrus"
)

var (
	authChain   = []func(*types.AuthCheckingContext) *types.AuthenticatedUser{}
	authChainMu sync.RWMutex
)

// AddProvider adds a provider to the global auth chain.
// DEPRECATED: Use AuthShimContext.AddProvider instead for per-context chains.
// This function is kept for backward compatibility but modifies a global chain
// that is shared across all contexts, which may cause unexpected behavior.
func AddProvider(check func(*types.AuthCheckingContext) *types.AuthenticatedUser) {
	authChainMu.Lock()
	defer authChainMu.Unlock()
	authChain = append(authChain, check)
}

// getRequestPathForLogging extracts path from request for logging
func getRequestPathForLogging(req *http.Request) string {
	if req != nil && req.URL != nil {
		return req.URL.Path
	}
	return ""
}

// runProviderWithPanicRecovery runs a provider function with panic recovery
func runProviderWithPanicRecovery(check func(*types.AuthCheckingContext) *types.AuthenticatedUser, authCtx *types.AuthCheckingContext, req *http.Request) *types.AuthenticatedUser {
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{
				"panic": r,
				"path":  getRequestPathForLogging(req),
			}).Errorf("Panic recovered in authentication provider")
		}
	}()
	return check(authCtx)
}

func runAuthChain(req *http.Request, cfg *types.Config) *types.AuthenticatedUser {
	// Extract context from request, or use background context if request is nil
	reqCtx := context.Background()
	if req != nil {
		reqCtx = req.Context()
	}

	authCtx := &types.AuthCheckingContext{
		Request:  req,
		Config:   cfg,
		Sessions: nil, // Use global session storage for backward compatibility
		Context:  reqCtx,
	}

	authChainMu.RLock()
	chain := make([]func(*types.AuthCheckingContext) *types.AuthenticatedUser, len(authChain))
	copy(chain, authChain)
	authChainMu.RUnlock()

	for _, check := range chain {
		user := runProviderWithPanicRecovery(check, authCtx, req)
		if user != nil && user.Username != "" {
			return user
		}
	}

	return nil
}

func AuthFromHttpReq(req *http.Request, cfg *types.Config) *types.AuthenticatedUser {
	user := runAuthChain(req, cfg)

	if user == nil || user.Username == "" {
		user = UserGuest(cfg)
	} else {
		user.BuildUserAcls(cfg)
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

	return user
}
