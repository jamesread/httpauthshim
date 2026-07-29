package haslocal

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/stretchr/testify/assert"
)

func localUsersConfig(users ...*authpublic.LocalUser) *authpublic.Config {
	return &authpublic.Config{
		LocalUsers: authpublic.LocalUsersConfig{
			Enabled: true,
			Users:   users,
		},
	}
}

func TestCheckUserFromApiKey_Disabled(t *testing.T) {
	cfg := &authpublic.Config{
		LocalUsers: authpublic.LocalUsersConfig{
			Enabled: false,
			Users: []*authpublic.LocalUser{
				{Username: "admin", ApiKey: "secret-key"},
			},
		},
	}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Bearer secret-key")

	user := CheckUserFromApiKey(&authpublic.AuthCheckingContext{Request: req, Config: cfg})
	assert.Nil(t, user)
}

func TestCheckUserFromApiKey_ValidKey(t *testing.T) {
	cfg := localUsersConfig(&authpublic.LocalUser{
		Username:  "admin",
		Usergroup: "admins",
		ApiKey:    "secret-key-123",
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Bearer secret-key-123")

	user := CheckUserFromApiKey(&authpublic.AuthCheckingContext{Request: req, Config: cfg})
	assert.NotNil(t, user)
	assert.Equal(t, "admin", user.Username)
	assert.Equal(t, "admins", user.UsergroupLine)
	assert.Equal(t, "local-apikey", user.Provider)
}

func TestCheckUserFromApiKey_InvalidKey(t *testing.T) {
	cfg := localUsersConfig(&authpublic.LocalUser{
		Username: "admin",
		ApiKey:   "secret-key-123",
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")

	user := CheckUserFromApiKey(&authpublic.AuthCheckingContext{Request: req, Config: cfg})
	assert.Nil(t, user)
}

func TestCheckUserFromApiKey_NoHeader(t *testing.T) {
	cfg := localUsersConfig(&authpublic.LocalUser{
		Username: "admin",
		ApiKey:   "secret-key-123",
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)

	user := CheckUserFromApiKey(&authpublic.AuthCheckingContext{Request: req, Config: cfg})
	assert.Nil(t, user)
}

func TestCheckUserFromApiKey_BasicPrefixIgnored(t *testing.T) {
	cfg := localUsersConfig(&authpublic.LocalUser{
		Username: "admin",
		ApiKey:   "secret-key-123",
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Basic secret-key-123")

	user := CheckUserFromApiKey(&authpublic.AuthCheckingContext{Request: req, Config: cfg})
	assert.Nil(t, user)
}

func TestCheckUserFromApiKey_EmptyApiKeyIgnored(t *testing.T) {
	cfg := localUsersConfig(&authpublic.LocalUser{
		Username: "admin",
		ApiKey:   "",
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Bearer ")

	user := CheckUserFromApiKey(&authpublic.AuthCheckingContext{Request: req, Config: cfg})
	assert.Nil(t, user)
}

func TestCheckUserFromApiKey_MultipleUsers(t *testing.T) {
	cfg := localUsersConfig(
		&authpublic.LocalUser{Username: "alice", Usergroup: "users", ApiKey: "alice-key"},
		&authpublic.LocalUser{Username: "bob", Usergroup: "admins", ApiKey: "bob-key"},
	)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Bearer bob-key")

	user := CheckUserFromApiKey(&authpublic.AuthCheckingContext{Request: req, Config: cfg})
	assert.NotNil(t, user)
	assert.Equal(t, "bob", user.Username)
	assert.Equal(t, "admins", user.UsergroupLine)
}
