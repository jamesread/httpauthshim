package hascallback

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCookieSID_Valid(t *testing.T) {
	lookup := func(_ context.Context, token string) (string, bool) {
		if token == "sid-1" {
			return "alice", true
		}
		return "", false
	}
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Cookie", "app-sid=sid-1")

	user := CookieSID("app-sid", lookup)(&authpublic.AuthCheckingContext{Request: req})
	require.NotNil(t, user)
	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, "callback-cookie", user.Provider)
	assert.Equal(t, "sid-1", user.SID)
}

func TestCookieSID_Unknown(t *testing.T) {
	lookup := func(_ context.Context, _ string) (string, bool) { return "", false }
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Cookie", "app-sid=missing")

	user := CookieSID("app-sid", lookup)(&authpublic.AuthCheckingContext{Request: req})
	assert.Nil(t, user)
}

func TestCookieSID_NoCookie(t *testing.T) {
	lookup := func(_ context.Context, _ string) (string, bool) { return "alice", true }
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)

	user := CookieSID("app-sid", lookup)(&authpublic.AuthCheckingContext{Request: req})
	assert.Nil(t, user)
}

func TestBearerToken_Valid(t *testing.T) {
	lookup := func(_ context.Context, token string) (string, bool) {
		return "bob", token == "key-1"
	}
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Bearer key-1")

	user := BearerToken(lookup)(&authpublic.AuthCheckingContext{Request: req})
	require.NotNil(t, user)
	assert.Equal(t, "bob", user.Username)
	assert.Equal(t, "callback-bearer", user.Provider)
}

func TestBearerToken_Missing(t *testing.T) {
	lookup := func(_ context.Context, _ string) (string, bool) { return "bob", true }
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)

	user := BearerToken(lookup)(&authpublic.AuthCheckingContext{Request: req})
	assert.Nil(t, user)
}

func TestBearerToken_NilLookup(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Bearer key-1")

	user := BearerToken(nil)(&authpublic.AuthCheckingContext{Request: req})
	assert.Nil(t, user)
}
