package hasoauth2

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authTypes "github.com/jamesread/httpauthshim/authpublic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestRedactedOAuthProviderHidesClientSecret(t *testing.T) {
	provider := &authTypes.OAuth2Provider{
		ClientID:     "client-id",
		ClientSecret: "super-secret",
		AuthUrl:      "https://example.com/auth",
	}

	redacted := redactedOAuthProvider(provider)
	assert.Equal(t, "client-id", redacted.ClientID)
	assert.Equal(t, "[REDACTED]", redacted.ClientSecret)
	assert.Equal(t, "https://example.com/auth", redacted.AuthUrl)
}

func TestIsCookieSecure(t *testing.T) {
	t.Run("TLS request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com/oauth/callback", nil)
		req.TLS = &tls.ConnectionState{}
		assert.True(t, isCookieSecure(req, &authTypes.Config{}))
	})

	t.Run("X-Forwarded-Proto https", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/oauth/callback", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		assert.True(t, isCookieSecure(req, &authTypes.Config{}))
	})

	t.Run("plain HTTP without proxy header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/oauth/callback", nil)
		assert.False(t, isCookieSecure(req, &authTypes.Config{}))
	})

	t.Run("config forces secure", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/oauth/callback", nil)
		cfg := &authTypes.Config{OAuth2CookieSecure: true}
		assert.True(t, isCookieSecure(req, cfg))
	})
}

func TestPKCEChallenge(t *testing.T) {
	verifier := "test-verifier-value"
	challenge := pkceChallenge(verifier)

	assert.NotEmpty(t, challenge)
	assert.NotEqual(t, verifier, challenge)
	assert.Equal(t, challenge, pkceChallenge(verifier))
}

func TestBuildAuthCodeURLWithPKCE(t *testing.T) {
	provider := &oauth2.Config{
		ClientID:    "client-id",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://example.com/auth",
		},
	}

	url := buildAuthCodeURL(provider, "state-value", "verifier-value", true)
	assert.Contains(t, url, "code_challenge=")
	assert.Contains(t, url, "code_challenge_method=S256")
	assert.Contains(t, url, "state=state-value")
}

func TestBuildAuthCodeURLWithoutPKCE(t *testing.T) {
	provider := &oauth2.Config{
		ClientID:    "client-id",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://example.com/auth",
		},
	}

	url := buildAuthCodeURL(provider, "state-value", "", false)
	assert.NotContains(t, url, "code_challenge=")
	assert.Contains(t, url, "state=state-value")
}

func TestValidateOAuthUsername(t *testing.T) {
	assert.False(t, validateOAuthUsername(""))
	assert.False(t, validateOAuthUsername("   "))
	assert.True(t, validateOAuthUsername("alice"))
}

func TestWriteOAuthClientError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeOAuthClientError(rec, http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.True(t, strings.Contains(rec.Body.String(), oauthClientError))
}

func TestOAuthPKCEEnabledByDefault(t *testing.T) {
	cfg := &authTypes.Config{}
	assert.True(t, cfg.OAuth2PKCEEnabled())

	cfg.OAuth2DisablePKCE = true
	assert.False(t, cfg.OAuth2PKCEEnabled())
}

func TestExchangeOptions(t *testing.T) {
	assert.Nil(t, exchangeOptions(""))
	opts := exchangeOptions("verifier")
	require.Len(t, opts, 1)
}
