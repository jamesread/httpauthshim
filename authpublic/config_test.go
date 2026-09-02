package authpublic

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/jamesread/httpauthshim/sessions"
	"github.com/stretchr/testify/assert"
)

func TestGetLocalSessionCookieName(t *testing.T) {
	assert.Equal(t, "auth-sid-local", (&Config{}).GetLocalSessionCookieName())
	assert.Equal(t, "my-local-sid", (&Config{LocalSessionCookieName: "my-local-sid"}).GetLocalSessionCookieName())
}

func TestGetOAuth2SessionCookieName(t *testing.T) {
	assert.Equal(t, "auth-sid-oauth", (&Config{}).GetOAuth2SessionCookieName())
	assert.Equal(t, "my-oauth-sid", (&Config{OAuth2SessionCookieName: "my-oauth-sid"}).GetOAuth2SessionCookieName())
}

func TestGetSessionTimeoutDefaults(t *testing.T) {
	assert.Equal(t, sessions.DefaultIdleTimeoutSeconds, (&Config{}).GetSessionIdleTimeoutSeconds())
	assert.Equal(t, sessions.DefaultAbsoluteTimeoutSeconds, (&Config{}).GetSessionAbsoluteTimeoutSeconds())
}

func TestGetSessionTimeoutOverrides(t *testing.T) {
	cfg := &Config{
		SessionIdleTimeoutSeconds:     600,
		SessionAbsoluteTimeoutSeconds: 7200,
	}
	assert.Equal(t, 600, cfg.GetSessionIdleTimeoutSeconds())
	assert.Equal(t, 7200, cfg.GetSessionAbsoluteTimeoutSeconds())
}

func TestGetSessionIdleTimeoutDisabled(t *testing.T) {
	cfg := &Config{SessionIdleTimeoutSeconds: -1}
	assert.Equal(t, 0, cfg.GetSessionIdleTimeoutSeconds())
}

func TestCookieSecureDefaults(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	assert.True(t, (&Config{}).CookieSecure(req))
	assert.True(t, (*Config)(nil).CookieSecure(req))
}

func TestConfigFromMap_Nil(t *testing.T) {
	cfg, err := ConfigFromMap(nil)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "", cfg.Jwt.Header)
}

func TestConfigFromMap_JWTAndHeaders(t *testing.T) {
	cfg, err := ConfigFromMap(map[string]any{
		"jwt": map[string]any{
			"header":     "Authorization",
			"hmacSecret": "s3cret",
		},
		"httpHeader": map[string]any{
			"username": "X-Username",
		},
		"mtls": map[string]any{
			"enabled":        true,
			"usernameFromCN": true,
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "Authorization", cfg.Jwt.Header)
	assert.Equal(t, "s3cret", cfg.Jwt.HmacSecret)
	assert.Equal(t, "X-Username", cfg.HttpHeader.Username)
	assert.True(t, cfg.Mtls.Enabled)
	assert.True(t, cfg.Mtls.UsernameFromCN)
}

func TestCookieSecureAllowInsecure(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	cfg := &Config{OAuth2AllowInsecureCookies: true}
	assert.False(t, cfg.CookieSecure(req))

	req.Header.Set("X-Forwarded-Proto", "https")
	assert.False(t, cfg.CookieSecure(req))

	cfg.TrustForwardedHeaders = true
	assert.True(t, cfg.CookieSecure(req))
}
