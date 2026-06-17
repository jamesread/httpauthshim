package hasoauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	authTypes "github.com/jamesread/httpauthshim/authpublic"
)

const oauthClientError = "OAuth2 authentication failed"

func writeOAuthClientError(w http.ResponseWriter, status int) {
	http.Error(w, oauthClientError, status)
}

func oauthProviderNames(providers map[string]*authTypes.OAuth2Provider) []string {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	return names
}

func redactedOAuthProvider(provider *authTypes.OAuth2Provider) authTypes.OAuth2Provider {
	if provider == nil {
		return authTypes.OAuth2Provider{}
	}

	copy := *provider
	if copy.ClientSecret != "" {
		copy.ClientSecret = "[REDACTED]"
	}
	return copy
}

func isCookieSecure(r *http.Request, cfg *authTypes.Config) bool {
	if cfg != nil && cfg.OAuth2CookieSecure {
		return true
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validateOAuthUsername(username string) bool {
	return strings.TrimSpace(username) != ""
}
