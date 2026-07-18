package haslocal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionID(t *testing.T) {
	id1, err := NewSessionID()
	require.NoError(t, err)
	id2, err := NewSessionID()
	require.NoError(t, err)
	assert.NotEmpty(t, id1)
	assert.NotEqual(t, id1, id2)
	assert.GreaterOrEqual(t, len(id1), 32)
}

func TestSetSessionCookie(t *testing.T) {
	cfg := &authpublic.Config{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://example.com/", nil)

	SetSessionCookie(rec, req, cfg, "sid-value")

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, cfg.GetLocalSessionCookieName(), cookies[0].Name)
	assert.Equal(t, "sid-value", cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
	assert.True(t, cookies[0].Secure)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
	assert.Equal(t, cfg.GetSessionAbsoluteTimeoutSeconds(), cookies[0].MaxAge)
}

func TestClearSessionCookie(t *testing.T) {
	cfg := &authpublic.Config{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	ClearSessionCookie(rec, req, cfg)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, -1, cookies[0].MaxAge)
	assert.Empty(t, cookies[0].Value)
}
