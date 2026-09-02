package hascallback

import (
	"context"
	"strings"

	"github.com/jamesread/httpauthshim/authpublic"
)

// Lookup resolves a cookie SID or Bearer token to a username.
// Return ok=false when the token is unknown.
type Lookup func(ctx context.Context, token string) (username string, ok bool)

const (
	providerCookie = "callback-cookie"
	providerBearer = "callback-bearer"
)

// CookieSID authenticates via a named cookie whose value is passed to lookup.
func CookieSID(cookieName string, lookup Lookup) func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	return func(ac *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
		token := cookieValue(ac, cookieName)
		return userFromLookup(ac, lookup, token, providerCookie, token)
	}
}

// BearerToken authenticates via Authorization: Bearer, passing the token to lookup.
func BearerToken(lookup Lookup) func(*authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	return func(ac *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
		token := bearerValue(ac)
		return userFromLookup(ac, lookup, token, providerBearer, "")
	}
}

func cookieValue(ac *authpublic.AuthCheckingContext, name string) string {
	if !ready(ac) || name == "" {
		return ""
	}
	c, err := ac.Request.Cookie(name)
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

func bearerValue(ac *authpublic.AuthCheckingContext) string {
	if !ready(ac) {
		return ""
	}
	return extractBearer(ac.Request.Header.Get("Authorization"))
}

func ready(ac *authpublic.AuthCheckingContext) bool {
	return ac != nil && ac.Request != nil
}

func userFromLookup(ac *authpublic.AuthCheckingContext, lookup Lookup, token, provider, sid string) *authpublic.AuthenticatedUser {
	if lookup == nil || token == "" {
		return nil
	}
	username, ok := lookup(requestContext(ac), token)
	if !ok || username == "" {
		return nil
	}
	return &authpublic.AuthenticatedUser{
		Username: username,
		Provider: provider,
		SID:      sid,
	}
}

func requestContext(ac *authpublic.AuthCheckingContext) context.Context {
	if ac != nil && ac.Context != nil {
		return ac.Context
	}
	if ac != nil && ac.Request != nil {
		return ac.Request.Context()
	}
	return context.Background()
}

func extractBearer(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}
