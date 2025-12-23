package authpublic

import (
	"context"
	"net/http"

	"github.com/jamesread/httpauthshim/sessions"
)

type AuthCheckingContext struct {
	Config    *Config
	Request   *http.Request
	Sessions  *sessions.SessionStorage // Optional: if nil, providers fall back to global session storage
	Context   context.Context           // Request context for cancellation and timeouts
}
