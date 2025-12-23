package hasbearer

import (
	"net/http/httptest"
	"testing"

	authpublic "github.com/jamesread/httpauthshim/authpublic"
	"github.com/stretchr/testify/assert"
)

func TestCheckUserFromBearerToken_Disabled(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: false,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.Nil(t, user)
}

func TestCheckUserFromBearerToken_NoHeader(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Tokens: map[string]*authpublic.BearerTokenUser{
				"test-token": {
					Username:  "testuser",
					Usergroup: "testgroup",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.Nil(t, user)
}

func TestCheckUserFromBearerToken_InvalidPrefix(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Tokens: map[string]*authpublic.BearerTokenUser{
				"test-token": {
					Username:  "testuser",
					Usergroup: "testgroup",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.Nil(t, user)
}

func TestCheckUserFromBearerToken_ValidToken(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Tokens: map[string]*authpublic.BearerTokenUser{
				"valid-token-123": {
					Username:  "testuser",
					Usergroup: "testgroup",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token-123")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.NotNil(t, user)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "testgroup", user.UsergroupLine)
	assert.Equal(t, "bearer", user.Provider)
}

func TestCheckUserFromBearerToken_InvalidToken(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Tokens: map[string]*authpublic.BearerTokenUser{
				"valid-token-123": {
					Username:  "testuser",
					Usergroup: "testgroup",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.Nil(t, user)
}

func TestCheckUserFromBearerToken_CustomHeader(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Header:  "X-Auth-Token",
			Tokens: map[string]*authpublic.BearerTokenUser{
				"custom-token": {
					Username:  "customuser",
					Usergroup: "customgroup",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Auth-Token", "Bearer custom-token")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.NotNil(t, user)
	assert.Equal(t, "customuser", user.Username)
	assert.Equal(t, "customgroup", user.UsergroupLine)
	assert.Equal(t, "bearer", user.Provider)
}

func TestCheckUserFromBearerToken_MultipleGroups(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Tokens: map[string]*authpublic.BearerTokenUser{
				"multi-group-token": {
					Username:  "multiuser",
					Usergroup: "group1 group2 group3",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer multi-group-token")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.NotNil(t, user)
	assert.Equal(t, "multiuser", user.Username)
	assert.Equal(t, "group1 group2 group3", user.UsergroupLine)
}

func TestCheckUserFromBearerToken_EmptyUsergroup(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Tokens: map[string]*authpublic.BearerTokenUser{
				"no-group-token": {
					Username:  "nousergroup",
					Usergroup: "",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer no-group-token")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.NotNil(t, user)
	assert.Equal(t, "nousergroup", user.Username)
	assert.Equal(t, "", user.UsergroupLine)
}

func TestCheckUserFromBearerToken_EmptyToken(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Tokens: map[string]*authpublic.BearerTokenUser{
				"valid-token": {
					Username:  "testuser",
					Usergroup: "testgroup",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer ")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.Nil(t, user)
}

func TestCheckUserFromBearerToken_TokenWithSpaces(t *testing.T) {
	cfg := &authpublic.Config{
		BearerToken: authpublic.BearerTokenConfig{
			Enabled: true,
			Tokens: map[string]*authpublic.BearerTokenUser{
				"token with spaces": {
					Username:  "spaceuser",
					Usergroup: "spacegroup",
				},
			},
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer token with spaces")

	authCtx := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromBearerToken(authCtx)
	assert.NotNil(t, user)
	assert.Equal(t, "spaceuser", user.Username)
}
