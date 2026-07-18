package haslocal

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/jamesread/httpauthshim/authpublic"
)

// NewSessionID generates a cryptographically random session ID (256 bits).
func NewSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SetSessionCookie sets the local session cookie with secure defaults:
// HttpOnly, SameSite=Lax, MaxAge=absolute timeout, Secure per Config.CookieSecure.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, cfg *authpublic.Config, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.GetLocalSessionCookieName(),
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cfg.GetSessionAbsoluteTimeoutSeconds(),
	})
}

// ClearSessionCookie expires the local session cookie.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request, cfg *authpublic.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.GetLocalSessionCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
