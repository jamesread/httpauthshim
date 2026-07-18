package hastrustedheaders

import (
	"net/http/httptest"
	"testing"

	authpublic "github.com/jamesread/httpauthshim/authpublic"
	"github.com/stretchr/testify/assert"
)

func TestCheckUserFromHeadersDisabledByDefault(t *testing.T) {
	cfg := &authpublic.Config{
		HttpHeader: authpublic.HttpHeaderConfig{
			Username:  "X-Username",
			UserGroup: "X-User-Group",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Username", "attacker")
	req.Header.Set("X-User-Group", "admin")

	user := CheckUserFromHeaders(&authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	})

	assert.Nil(t, user)
}

func TestCheckUserFromHeadersEnabledFromTrustedProxy(t *testing.T) {
	cfg := &authpublic.Config{
		HttpHeader: authpublic.HttpHeaderConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"127.0.0.1/32", "::1/128"},
			Username:          "X-Username",
			UserGroup:         "X-User-Group",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Username", "alice")
	req.Header.Set("X-User-Group", "admin")

	user := CheckUserFromHeaders(&authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	})

	assert.NotNil(t, user)
	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, "admin", user.UsergroupLine)
	assert.Equal(t, "trusted-header", user.Provider)
}

func TestCheckUserFromHeadersRejectsUntrustedProxy(t *testing.T) {
	cfg := &authpublic.Config{
		HttpHeader: authpublic.HttpHeaderConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			Username:          "X-Username",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Username", "alice")

	user := CheckUserFromHeaders(&authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	})

	assert.Nil(t, user)
}

func TestCheckUserFromHeadersIgnoresClientProviderHeader(t *testing.T) {
	cfg := &authpublic.Config{
		HttpHeader: authpublic.HttpHeaderConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"127.0.0.1/32"},
			Username:          "X-Username",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("X-Username", "alice")
	req.Header.Set("provider", "oauth2")

	user := CheckUserFromHeaders(&authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	})

	assert.NotNil(t, user)
	assert.Equal(t, "trusted-header", user.Provider)
}
