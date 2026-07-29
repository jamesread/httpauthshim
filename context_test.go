package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/jamesread/httpauthshim/providers/haslocal"
	"github.com/jamesread/httpauthshim/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAuthContext(t *testing.T, cfg *authpublic.Config) *AuthShimContext {
	t.Helper()
	if cfg == nil {
		cfg = &authpublic.Config{}
	}
	cfg.BaseDir = t.TempDir()

	storage := sessions.NewSessionStorage(sessions.NewYAMLPersistence())
	ctx, err := NewAuthShimContext(cfg, storage)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Shutdown() })
	return ctx
}

func TestOnAuthenticated_Guest(t *testing.T) {
	ctx := newTestAuthContext(t, nil)

	var calledWith *authpublic.AuthenticatedUser
	ctx.OnAuthenticated(func(user *authpublic.AuthenticatedUser, cfg *authpublic.Config) {
		calledWith = user
		assert.NotNil(t, cfg)
		user.Acls = append(user.Acls, "enriched-guest")
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	user := ctx.AuthFromHttpReq(req)

	assert.True(t, user.IsGuest())
	assert.Same(t, user, calledWith)
	assert.Contains(t, user.Acls, "enriched-guest")
}

func TestOnAuthenticated_AfterBuildUserAcls(t *testing.T) {
	cfg := &authpublic.Config{
		AccessControlLists: []authpublic.AccessControlList{
			{Name: "admins", MatchUsernames: []string{"alice"}},
		},
	}
	ctx := newTestAuthContext(t, cfg)

	ctx.AddProvider(func(_ *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
		return &authpublic.AuthenticatedUser{
			Username:      "alice",
			UsergroupLine: "staff",
			Provider:      "test",
		}
	})

	var aclsAtHook []string
	ctx.OnAuthenticated(func(user *authpublic.AuthenticatedUser, _ *authpublic.Config) {
		aclsAtHook = append([]string(nil), user.Acls...)
		user.Acls = append(user.Acls, "custom")
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	user := ctx.AuthFromHttpReq(req)

	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, []string{"admins"}, aclsAtHook)
	assert.Equal(t, []string{"admins", "custom"}, user.Acls)
}

func TestOnAuthenticated_MultipleHooks(t *testing.T) {
	ctx := newTestAuthContext(t, nil)

	order := []string{}
	ctx.OnAuthenticated(func(user *authpublic.AuthenticatedUser, _ *authpublic.Config) {
		order = append(order, "first")
		user.Acls = append(user.Acls, "first")
	})
	ctx.OnAuthenticated(func(user *authpublic.AuthenticatedUser, _ *authpublic.Config) {
		order = append(order, "second")
		user.Acls = append(user.Acls, "second")
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	user := ctx.AuthFromHttpReq(req)

	assert.Equal(t, []string{"first", "second"}, order)
	assert.Equal(t, []string{"first", "second"}, user.Acls)
}

func TestOnAuthenticated_NilIgnored(t *testing.T) {
	ctx := newTestAuthContext(t, nil)
	assert.NotPanics(t, func() {
		ctx.OnAuthenticated(nil)
		_ = ctx.AuthFromHttpReq(httptest.NewRequestWithContext(context.Background(), "GET", "/", nil))
	})
}

func TestValidateJwtRequiresAudAndIssuer(t *testing.T) {
	storage := sessions.NewSessionStorage(sessions.NewYAMLPersistence())
	cfg := &authpublic.Config{
		BaseDir: t.TempDir(),
		Jwt: authpublic.JwtConfig{
			HmacSecret: "secret",
		},
	}
	_, err := NewAuthShimContext(cfg, storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aud")

	cfg.Jwt.Aud = "my-aud"
	_, err = NewAuthShimContext(cfg, storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")

	cfg.Jwt.Issuer = "my-issuer"
	ctx, err := NewAuthShimContext(cfg, storage)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Shutdown() })
}

func TestValidateHttpHeaderRequiresTrustedProxyCIDRs(t *testing.T) {
	storage := sessions.NewSessionStorage(sessions.NewYAMLPersistence())
	cfg := &authpublic.Config{
		BaseDir: t.TempDir(),
		HttpHeader: authpublic.HttpHeaderConfig{
			Enabled:  true,
			Username: "X-User",
		},
	}
	_, err := NewAuthShimContext(cfg, storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trustedProxyCIDRs")

	cfg.HttpHeader.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	ctx, err := NewAuthShimContext(cfg, storage)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Shutdown() })
}

func TestAuthFromHeaders_Guest(t *testing.T) {
	ctx := newTestAuthContext(t, nil)
	user := ctx.AuthFromHeaders(nil)
	assert.True(t, user.IsGuest())
}

func TestAuthFromHeaders_ApiKey(t *testing.T) {
	cfg := &authpublic.Config{
		LocalUsers: authpublic.LocalUsersConfig{
			Enabled: true,
			Users: []*authpublic.LocalUser{
				{Username: "admin", Usergroup: "admins", ApiKey: "secret-key"},
			},
		},
	}
	ctx := newTestAuthContext(t, cfg)
	ctx.AddProvider(haslocal.CheckUserFromApiKey)

	headers := http.Header{}
	headers.Set("Authorization", "Bearer secret-key")

	user := ctx.AuthFromHeaders(headers)
	assert.Equal(t, "admin", user.Username)
	assert.Equal(t, "admins", user.UsergroupLine)
	assert.Equal(t, "local-apikey", user.Provider)
}

func TestAuthFromHeaders_RunsEnrichHooks(t *testing.T) {
	ctx := newTestAuthContext(t, nil)
	ctx.OnAuthenticated(func(user *authpublic.AuthenticatedUser, _ *authpublic.Config) {
		user.Acls = append(user.Acls, "from-headers")
	})

	user := ctx.AuthFromHeaders(http.Header{})
	assert.True(t, user.IsGuest())
	assert.Contains(t, user.Acls, "from-headers")
}
