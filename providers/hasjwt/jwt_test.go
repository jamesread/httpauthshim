package hasjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"

	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/stretchr/testify/assert"
)

func generateRSAKeyPair(t *testing.T) (*rsa.PrivateKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubKey := &privateKey.PublicKey
	pkixPubKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkixPubKey,
		},
	)

	return privateKey, pubPem
}

func createKeys(t *testing.T) (*rsa.PrivateKey, string) {
	tmpFile, err := os.CreateTemp(os.TempDir(), "olivetin-jwt-")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = tmpFile.Close() }()

	t.Logf("Created File: %s", tmpFile.Name())

	privateKey, pubPem := generateRSAKeyPair(t)

	if err := os.WriteFile(tmpFile.Name(), pubPem, 0644); err != nil {
		t.Fatalf("error when dumping pubKey: %s \n", err)
	}

	return privateKey, tmpFile.Name()
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()

	return mux
}

func createJWTTokenWithExpiration(t *testing.T, privateKey *rsa.PrivateKey, expire int64) string {
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["nbf"] = time.Now().Unix() - 1000
	claims["exp"] = time.Now().Unix() + expire
	claims["sub"] = "test"
	claims["olivetinGroup"] = "test"

	tokenStr, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign JWT token: %v", err)
	}
	return tokenStr
}

func setupJWTTestHandler(t *testing.T, cfg *authpublic.Config) http.Handler {
	mux := newMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		context := &authpublic.AuthCheckingContext{
			Request: r,
			Config:  cfg,
		}
		user := CheckUserFromJwtHeader(context)

		if user == nil {
			w.WriteHeader(403)
			return
		}

		assert.Equal(t, "test", user.Username)
		assert.Equal(t, "test", user.UsergroupLine)
	})
	return mux
}

func verifyJWTResponse(t *testing.T, res *http.Response, expectCode int) {
	defer func() { _ = res.Body.Close() }()
	assert.Equal(t, expectCode, res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	t.Logf("Response body: %s", string(body))
}

func testJwkValidation(t *testing.T, expire int64, expectCode int) {
	privateKey, publicKeyPath := createKeys(t)
	defer func() { _ = os.Remove(publicKeyPath) }()

	cfg := &authpublic.Config{}
	cfg.Jwt.PubKeyPath = publicKeyPath
	cfg.Jwt.ClaimUsername = "sub"
	cfg.Jwt.ClaimUserGroup = "olivetinGroup"
	cfg.Jwt.Header = "Authorization"

	tokenStr := createJWTTokenWithExpiration(t, privateKey, expire)
	handler := setupJWTTestHandler(t, cfg)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	res := makeJWTRequest(t, srv, tokenStr)
	verifyJWTResponse(t, res, expectCode)
}

func TestJWTSignatureVerificationSucceeds(t *testing.T) {
	testJwkValidation(t, 1000, 200)
}

func TestJWTSignatureVerificationFails(t *testing.T) {
	testJwkValidation(t, -500, 403)
}

func createJWTTokenWithGroups(t *testing.T, privateKey *rsa.PrivateKey, groups interface{}) string {
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["nbf"] = time.Now().Unix() - 1000
	claims["exp"] = time.Now().Unix() + 2000
	claims["sub"] = "test"
	claims["olivetinGroup"] = groups

	tokenStr, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign JWT token: %v", err)
	}
	return tokenStr
}

func makeJWTRequest(t *testing.T, srv *httptest.Server, tokenStr string) *http.Response {
	req, err := http.NewRequest("GET", srv.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Client err: %+v", err)
	}
	return res
}

func TestJWTHeader(t *testing.T) {
	privateKey, publicKeyPath := createKeys(t)
	defer func() { _ = os.Remove(publicKeyPath) }()

	cfg := &authpublic.Config{}
	cfg.Jwt.PubKeyPath = publicKeyPath
	cfg.Jwt.ClaimUsername = "sub"
	cfg.Jwt.ClaimUserGroup = "olivetinGroup"
	cfg.Jwt.Header = "Authorization"

	tokenStr := createJWTTokenWithGroups(t, privateKey, []string{"test", "test2"})

	mux := newMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		context := &authpublic.AuthCheckingContext{
			Request: r,
			Config:  cfg,
		}
		user := CheckUserFromJwtHeader(context)

		if user == nil {
			w.WriteHeader(403)
			return
		}

		assert.Equal(t, "test", user.Username)
		assert.Equal(t, "test test2", user.UsergroupLine)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := makeJWTRequest(t, srv, tokenStr)
	defer func() { _ = res.Body.Close() }()

	assert.Equal(t, 200, res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	t.Logf("Response body: %s", string(body))
}

func baseJWTConfig(publicKeyPath string) *authpublic.Config {
	cfg := &authpublic.Config{}
	cfg.Jwt.PubKeyPath = publicKeyPath
	cfg.Jwt.ClaimUsername = "sub"
	cfg.Jwt.ClaimUserGroup = "olivetinGroup"
	cfg.Jwt.Header = "Authorization"
	return cfg
}

func checkUserFromBearerToken(t *testing.T, cfg *authpublic.Config, tokenStr string) *authpublic.AuthenticatedUser {
	t.Helper()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	return CheckUserFromJwtHeader(&authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	})
}

func TestJWTRejectsTokenWithoutExp(t *testing.T) {
	privateKey, publicKeyPath := createKeys(t)
	defer func() { _ = os.Remove(publicKeyPath) }()

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "test"
	tokenStr, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	user := checkUserFromBearerToken(t, baseJWTConfig(publicKeyPath), tokenStr)
	assert.Nil(t, user)
}

func TestJWTRejectsWrongAudience(t *testing.T) {
	privateKey, publicKeyPath := createKeys(t)
	defer func() { _ = os.Remove(publicKeyPath) }()

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "test"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["aud"] = "wrong-audience"
	tokenStr, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	cfg := baseJWTConfig(publicKeyPath)
	cfg.Jwt.Aud = "expected-audience"

	user := checkUserFromBearerToken(t, cfg, tokenStr)
	assert.Nil(t, user)
}

func TestJWTAcceptsMatchingAudience(t *testing.T) {
	privateKey, publicKeyPath := createKeys(t)
	defer func() { _ = os.Remove(publicKeyPath) }()

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "test"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["aud"] = "expected-audience"
	tokenStr, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	cfg := baseJWTConfig(publicKeyPath)
	cfg.Jwt.Aud = "expected-audience"

	user := checkUserFromBearerToken(t, cfg, tokenStr)
	assert.NotNil(t, user)
	assert.Equal(t, "test", user.Username)
}

func TestJWTRejectsWrongIssuer(t *testing.T) {
	privateKey, publicKeyPath := createKeys(t)
	defer func() { _ = os.Remove(publicKeyPath) }()

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "test"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["iss"] = "wrong-issuer"
	tokenStr, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	cfg := baseJWTConfig(publicKeyPath)
	cfg.Jwt.Issuer = "expected-issuer"

	user := checkUserFromBearerToken(t, cfg, tokenStr)
	assert.Nil(t, user)
}

func TestHMACRejectsTokenWithoutExp(t *testing.T) {
	secret := "test-hmac-secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "attacker",
	})
	tokenStr, err := token.SignedString([]byte(secret))
	assert.NoError(t, err)

	cfg := &authpublic.Config{
		Jwt: authpublic.JwtConfig{
			HmacSecret:    secret,
			ClaimUsername: "sub",
			Header:        "Authorization",
		},
	}

	user := checkUserFromBearerToken(t, cfg, tokenStr)
	assert.Nil(t, user)
}

func TestHMACAcceptsValidToken(t *testing.T) {
	secret := "test-hmac-secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secret))
	assert.NoError(t, err)

	cfg := &authpublic.Config{
		Jwt: authpublic.JwtConfig{
			HmacSecret:    secret,
			ClaimUsername: "sub",
			Header:        "Authorization",
		},
	}

	user := checkUserFromBearerToken(t, cfg, tokenStr)
	assert.NotNil(t, user)
	assert.Equal(t, "alice", user.Username)
}
