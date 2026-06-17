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
	req.Header.Set("X-Username", "attacker")
	req.Header.Set("X-User-Group", "admin")

	user := CheckUserFromHeaders(&authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	})

	assert.Nil(t, user)
}

func TestCheckUserFromHeadersEnabled(t *testing.T) {
	cfg := &authpublic.Config{
		HttpHeader: authpublic.HttpHeaderConfig{
			Enabled:   true,
			Username:  "X-Username",
			UserGroup: "X-User-Group",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
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

func TestCheckUserFromHeadersIgnoresClientProviderHeader(t *testing.T) {
	cfg := &authpublic.Config{
		HttpHeader: authpublic.HttpHeaderConfig{
			Enabled:  true,
			Username: "X-Username",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Username", "alice")
	req.Header.Set("provider", "oauth2")

	user := CheckUserFromHeaders(&authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	})

	assert.NotNil(t, user)
	assert.Equal(t, "trusted-header", user.Provider)
}
