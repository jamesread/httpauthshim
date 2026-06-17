package hasoauth2

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	authTypes "github.com/jamesread/httpauthshim/authpublic"
	"github.com/jamesread/httpauthshim/sessions"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type OAuth2Handler struct {
	cfg                 *authTypes.Config
	sessionStorage      *sessions.SessionStorage  // Instance-based session storage
	callbackStates      map[string]*callbackState // Temporary state for OAuth callback flow
	callbackStatesMutex sync.RWMutex              // Protects callbackStates map
	registeredProviders map[string]*oauth2.Config
	shutdownChan        chan struct{} // Channel to signal shutdown
	shutdownOnce        sync.Once     // Ensures shutdown is called only once

	// SessionStorage returns the session storage (exported for reuse by OIDC)
	SessionStorage func() *sessions.SessionStorage

	// Cached HTTP clients per provider (keyed by provider name)
	httpClients   map[string]*http.Client
	httpClientsMu sync.RWMutex // Protects httpClients map

	// Cached cert bundles per provider (keyed by cert bundle path)
	certBundles      map[string]*x509.CertPool
	certBundlesMu    sync.RWMutex         // Protects certBundles map
	certBundleMtimes map[string]time.Time // Track file modification times for cache invalidation
}

// NewOAuth2Handler creates a new OAuth2 handler with instance-based session storage.
// If sessionStorage is nil, it will fall back to global session storage (deprecated).
func NewOAuth2Handler(cfg *authTypes.Config, sessionStorage *sessions.SessionStorage) *OAuth2Handler {
	h := &OAuth2Handler{
		cfg:            cfg,
		sessionStorage: sessionStorage,
		shutdownChan:   make(chan struct{}),
		SessionStorage: func() *sessions.SessionStorage {
			return sessionStorage
		},
	}

	h.callbackStates = make(map[string]*callbackState)
	h.registeredProviders = make(map[string]*oauth2.Config)
	h.httpClients = make(map[string]*http.Client)
	h.certBundles = make(map[string]*x509.CertPool)
	h.certBundleMtimes = make(map[string]time.Time)

	log.Infof("OAuth2 providers registered: %v", oauthProviderNames(cfg.OAuth2Providers))

	for providerName, providerConfig := range cfg.OAuth2Providers {
		completeProviderConfig(providerName, providerConfig)

		if providerConfig.InsecureSkipVerify {
			log.WithFields(log.Fields{
				"provider": providerName,
			}).Warn("OAuth2 provider has InsecureSkipVerify enabled; TLS certificate verification is disabled")
		}

		newConfig := &oauth2.Config{
			ClientID:     providerConfig.ClientID,
			ClientSecret: providerConfig.ClientSecret,
			Scopes:       providerConfig.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  providerConfig.AuthUrl,
				TokenURL: providerConfig.TokenUrl,
			},
			RedirectURL: cfg.OAuth2RedirectURL,
		}

		h.registeredProviders[providerName] = newConfig

		log.WithFields(log.Fields{
			"provider": providerName,
			"config":   redactedOAuthProvider(providerConfig),
		}).Debug("OAuth2 provider registered")
	}

	// Start cleanup goroutine to remove expired callback states
	go h.cleanupExpiredStates()

	return h
}

// Shutdown stops the OAuth2 handler's cleanup goroutine and clears callback states.
// This should be called when the handler is no longer needed to prevent goroutine leaks.
//
// IMPORTANT: This method must be called before the handler is garbage collected,
// otherwise the cleanup goroutine will leak. Consider using runtime.SetFinalizer
// or ensuring Shutdown is called in your application's cleanup logic.
func (h *OAuth2Handler) Shutdown() {
	h.shutdownOnce.Do(func() {
		close(h.shutdownChan)
		h.callbackStatesMutex.Lock()
		defer h.callbackStatesMutex.Unlock()
		h.callbackStates = make(map[string]*callbackState)

		// Close HTTP client transports to release connections
		h.httpClientsMu.Lock()
		for _, client := range h.httpClients {
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}
		h.httpClients = make(map[string]*http.Client)
		h.httpClientsMu.Unlock()

		log.Debug("OAuth2 handler shutdown complete")
	})
}

// callbackState stores temporary state needed during OAuth callback flow
type callbackState struct {
	providerConfig *oauth2.Config
	providerName   string
	expiresAt      time.Time
	codeVerifier   string // PKCE code verifier (empty when PKCE disabled)
}

func assignIfEmpty(target *string, value string) {
	if *target == "" {
		*target = value
	}
}

func completeProviderConfig(providerName string, providerConfig *authTypes.OAuth2Provider) {
	dbConfig, ok := oauth2ProviderDatabase[providerName]

	if ok {
		assignIfEmpty(&providerConfig.Name, dbConfig.Name)
		assignIfEmpty(&providerConfig.Title, dbConfig.Title)
		assignIfEmpty(&providerConfig.WhoamiUrl, dbConfig.WhoamiUrl)
		assignIfEmpty(&providerConfig.TokenUrl, dbConfig.TokenUrl)
		assignIfEmpty(&providerConfig.AuthUrl, dbConfig.AuthUrl)
		assignIfEmpty(&providerConfig.Icon, dbConfig.Icon)
		assignIfEmpty(&providerConfig.UsernameField, dbConfig.UsernameField)

		if providerConfig.Scopes == nil {
			providerConfig.Scopes = dbConfig.Scopes
		}
	} else {
		log.Warnf("Provider not found in database: %v", providerName)
	}
}

// GetOAuth2Config returns the OAuth2 config for a provider (exported for reuse by OIDC)
func (h *OAuth2Handler) GetOAuth2Config(providerName string) (*oauth2.Config, error) {
	return h.getOAuth2Config(providerName)
}

func (h *OAuth2Handler) getOAuth2Config(providerName string) (*oauth2.Config, error) {
	config, ok := h.registeredProviders[providerName]

	if !ok {
		return nil, fmt.Errorf("provider not found in config: %v", providerName)
	}

	return config, nil
}

// cleanupExpiredStates periodically removes expired callback states to prevent unbounded memory growth
// cleanupExpiredCallbackStates removes expired callback states
func (h *OAuth2Handler) cleanupExpiredCallbackStates(now time.Time) int {
	cleanedCount := 0
	for state, cbState := range h.callbackStates {
		if now.After(cbState.expiresAt) {
			delete(h.callbackStates, state)
			cleanedCount++
		}
	}
	return cleanedCount
}

// logOAuth2CleanupResults logs cleanup results and warnings
func logOAuth2CleanupResults(cleanedCount, stateCount int) {
	if cleanedCount > 0 {
		log.WithFields(log.Fields{
			"cleanedStates":   cleanedCount,
			"remainingStates": stateCount,
		}).Debugf("OAuth2 expired callback states cleaned up")
	}

	if stateCount > 1000 {
		log.WithFields(log.Fields{
			"stateCount": stateCount,
		}).Warn("OAuth2 callback state map is large - may indicate high login rate or cleanup issues")
	}
}

// performOAuth2StateCleanup performs a single cleanup cycle
func (h *OAuth2Handler) performOAuth2StateCleanup() {
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{
				"panic": r,
			}).Errorf("Panic recovered in OAuth2 cleanup goroutine, continuing")
		}
	}()

	now := time.Now()
	h.callbackStatesMutex.Lock()
	cleanedCount := h.cleanupExpiredCallbackStates(now)
	stateCount := len(h.callbackStates)
	h.callbackStatesMutex.Unlock()

	logOAuth2CleanupResults(cleanedCount, stateCount)
}

func (h *OAuth2Handler) cleanupExpiredStates() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-h.shutdownChan:
			return
		case <-ticker.C:
			h.performOAuth2StateCleanup()
		}
	}
}

// RandString generates a random base64-encoded string (exported for reuse by OIDC)
func RandString(nByte int) (string, error) {
	return randString(nByte)
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

func (h *OAuth2Handler) setOAuthCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   31556952, // 1 year (matches session expiry)
		Secure:   isCookieSecure(r, h.cfg),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode, // Allow cookie to be sent on redirects from OAuth provider
	}

	http.SetCookie(w, cookie)
	log.WithFields(log.Fields{
		"cookieName":  name,
		"cookieValue": previewValue(value),
		"secure":      cookie.Secure,
		"sameSite":    cookie.SameSite,
		"maxAge":      cookie.MaxAge,
	}).Debug("OAuth2 cookie set")
}

func buildAuthCodeURL(provider *oauth2.Config, state, codeVerifier string, pkceEnabled bool) string {
	if !pkceEnabled || codeVerifier == "" {
		return provider.AuthCodeURL(state)
	}

	return provider.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (h *OAuth2Handler) storeCallbackState(state, providerName string, provider *oauth2.Config, codeVerifier string) {
	h.callbackStatesMutex.Lock()
	defer h.callbackStatesMutex.Unlock()

	h.callbackStates[state] = &callbackState{
		providerConfig: provider,
		providerName:   providerName,
		expiresAt:      time.Now().Add(15 * time.Minute),
		codeVerifier:   codeVerifier,
	}
}

func (h *OAuth2Handler) HandleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"provider": r.URL.Query().Get("provider"),
	}).Debug("OAuth2 login request")

	state, err := RandString(16)
	if err != nil {
		log.WithError(err).Error("OAuth2 failed to generate state")
		writeOAuthClientError(w, http.StatusInternalServerError)
		return
	}

	providerName := r.URL.Query().Get("provider")
	provider, err := h.GetOAuth2Config(providerName)
	if err != nil {
		log.WithFields(log.Fields{
			"provider": providerName,
			"error":    err,
		}).Error("OAuth2 failed to get provider config")
		writeOAuthClientError(w, http.StatusBadRequest)
		return
	}

	codeVerifier := ""
	if h.cfg.OAuth2PKCEEnabled() {
		codeVerifier, err = RandString(32)
		if err != nil {
			log.WithError(err).Error("OAuth2 failed to generate PKCE verifier")
			writeOAuthClientError(w, http.StatusInternalServerError)
			return
		}
	}

	h.storeCallbackState(state, providerName, provider, codeVerifier)
	h.setOAuthCallbackCookie(w, r, h.cfg.GetOAuth2SessionCookieName(), state)

	loginURL := buildAuthCodeURL(provider, state, codeVerifier, h.cfg.OAuth2PKCEEnabled())
	log.WithFields(log.Fields{
		"provider": providerName,
		"state":    previewValue(state),
		"pkce":     codeVerifier != "",
	}).Debug("OAuth2 redirecting to provider")

	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *OAuth2Handler) validateStateMatch(queryState, cookieState string) bool {
	return queryState == cookieState
}

func (h *OAuth2Handler) checkOAuthCallbackCookie(w http.ResponseWriter, r *http.Request) (*callbackState, string, bool) {
	cookie, err := r.Cookie(h.cfg.GetOAuth2SessionCookieName())
	if err != nil {
		log.WithError(err).Error("OAuth2 failed to get state cookie")
		writeOAuthClientError(w, http.StatusBadRequest)
		return nil, "", false
	}

	state := cookie.Value
	queryState := r.URL.Query().Get("state")

	log.WithFields(log.Fields{
		"cookieState": previewValue(state),
		"queryState":  previewValue(queryState),
		"statesMatch": state == queryState,
	}).Debug("OAuth2 callback state validation")

	if !h.validateStateMatch(queryState, state) {
		log.Error("OAuth2 callback state mismatch")
		writeOAuthClientError(w, http.StatusBadRequest)
		return nil, state, false
	}

	h.callbackStatesMutex.Lock()
	callbackState, ok := h.callbackStates[state]
	if !ok {
		h.callbackStatesMutex.Unlock()
		log.WithFields(log.Fields{
			"state":               previewValue(state),
			"callbackStatesCount": len(h.callbackStates),
		}).Error("OAuth2 callback state not found in server")
		writeOAuthClientError(w, http.StatusBadRequest)
		return nil, state, false
	}

	if time.Now().After(callbackState.expiresAt) {
		delete(h.callbackStates, state)
		h.callbackStatesMutex.Unlock()
		log.WithFields(log.Fields{
			"state":     previewValue(state),
			"expiresAt": callbackState.expiresAt,
		}).Error("OAuth2 callback state expired")
		writeOAuthClientError(w, http.StatusBadRequest)
		return nil, state, false
	}

	delete(h.callbackStates, state)
	h.callbackStatesMutex.Unlock()

	log.WithFields(log.Fields{
		"state":    previewValue(state),
		"provider": callbackState.providerName,
	}).Debug("OAuth2 callback state validated successfully and marked as used")

	return callbackState, state, true
}

// getOAuthCertBundle gets or loads the cert bundle for a provider, with caching and file change detection
// checkCachedCertBundle checks if cached cert bundle is still valid
func (h *OAuth2Handler) checkCachedCertBundle(certPath string) (*x509.CertPool, bool) {
	h.certBundlesMu.RLock()
	cachedBundle, exists := h.certBundles[certPath]
	cachedMtime := h.certBundleMtimes[certPath]
	h.certBundlesMu.RUnlock()

	if !exists {
		return nil, false
	}

	// Check if file has been modified
	stat, err := os.Stat(certPath)
	if err != nil {
		return nil, false
	}

	if stat.ModTime().Equal(cachedMtime) {
		return cachedBundle, true
	}

	log.WithFields(log.Fields{
		"path": certPath,
	}).Debugf("OAuth2 Cert Bundle file modified, reloading")
	return nil, false
}

// loadCertBundleFromFile loads cert bundle from file
func loadCertBundleFromFile(certPath string) (*x509.CertPool, time.Time, error) {
	caCert, err := os.ReadFile(certPath)
	if err != nil {
		log.WithFields(log.Fields{
			"path":  certPath,
			"error": err,
		}).Errorf("OAuth2 Cert Bundle - failed to read file, will fall back to system root CAs")
		return nil, time.Time{}, err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.WithFields(log.Fields{
			"path": certPath,
		}).Errorf("OAuth2 Cert Bundle - failed to append certificates from PEM, will fall back to system root CAs")
		return nil, time.Time{}, fmt.Errorf("failed to append certificates from PEM")
	}

	var mtime time.Time
	if stat, err := os.Stat(certPath); err == nil {
		mtime = stat.ModTime()
	}

	return caCertPool, mtime, nil
}

func (h *OAuth2Handler) getOAuthCertBundle(providerConfig *authTypes.OAuth2Provider) *x509.CertPool {
	if providerConfig.CertBundlePath == "" {
		return nil
	}

	// Check cache first
	if cachedBundle, valid := h.checkCachedCertBundle(providerConfig.CertBundlePath); valid {
		return cachedBundle
	}

	// Load cert bundle from file
	caCertPool, mtime, err := loadCertBundleFromFile(providerConfig.CertBundlePath)
	if err != nil {
		return nil
	}

	// Cache the bundle

	h.certBundlesMu.Lock()
	h.certBundles[providerConfig.CertBundlePath] = caCertPool
	h.certBundleMtimes[providerConfig.CertBundlePath] = mtime
	h.certBundlesMu.Unlock()

	log.WithFields(log.Fields{
		"path": providerConfig.CertBundlePath,
	}).Debugf("OAuth2 Cert Bundle loaded and cached successfully")
	return caCertPool
}

// GetOrCreateHttpClient gets or creates a cached HTTP client for a provider (exported for reuse by OIDC)
func (h *OAuth2Handler) GetOrCreateHttpClient(providerName string, providerConfig *authTypes.OAuth2Provider) *http.Client {
	return h.getOrCreateHttpClient(providerName, providerConfig)
}

// getOrCreateHttpClient gets or creates a cached HTTP client for a provider
func (h *OAuth2Handler) getOrCreateHttpClient(providerName string, providerConfig *authTypes.OAuth2Provider) *http.Client {
	// Check cache first (with read lock)
	h.httpClientsMu.RLock()
	if client, exists := h.httpClients[providerName]; exists {
		h.httpClientsMu.RUnlock()
		return client
	}
	h.httpClientsMu.RUnlock()

	// Double-check pattern: acquire write lock and check again
	h.httpClientsMu.Lock()
	defer h.httpClientsMu.Unlock()

	// Check again after acquiring write lock (another goroutine may have created it)
	if client, exists := h.httpClients[providerName]; exists {
		return client
	}

	// Create new client
	timeout := time.Duration(min(3, providerConfig.CallbackTimeout)) * time.Second

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: providerConfig.InsecureSkipVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Set cert bundle if configured
	if providerConfig.CertBundlePath != "" {
		certPool := h.getOAuthCertBundle(providerConfig)
		if certPool != nil {
			transport.TLSClientConfig.RootCAs = certPool
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	// Cache the client
	h.httpClients[providerName] = client

	return client
}

func exchangeOptions(codeVerifier string) []oauth2.AuthCodeOption {
	if codeVerifier == "" {
		return nil
	}
	return []oauth2.AuthCodeOption{oauth2.VerifierOption(codeVerifier)}
}

func (h *OAuth2Handler) registerOAuthSession(sessionID, username, usergroup string) {
	if h.sessionStorage != nil {
		h.sessionStorage.RegisterSession(h.cfg.GetDir(), h.cfg.GetSessionFileName(), "oauth2", sessionID, username, usergroup)
		return
	}
	sessions.RegisterUserSession(h.cfg, "oauth2", sessionID, username, usergroup)
}

func (h *OAuth2Handler) fetchOAuthUserInfo(ctx context.Context, registeredState *callbackState, code string, providerConfig *authTypes.OAuth2Provider) (*UserInfo, error) {
	baseClient := h.GetOrCreateHttpClient(registeredState.providerName, providerConfig)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, baseClient)

	tok, err := registeredState.providerConfig.Exchange(ctx, code, exchangeOptions(registeredState.codeVerifier)...)
	if err != nil {
		return nil, err
	}

	baseTransport := baseClient.Transport.(*http.Transport)
	userInfoClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: registeredState.providerConfig.TokenSource(ctx, tok),
			Base:   baseTransport,
		},
		Timeout: baseClient.Timeout,
	}

	return getUserInfo(h.cfg, userInfoClient, providerConfig), nil
}

func (h *OAuth2Handler) completeOAuthLogin(w http.ResponseWriter, r *http.Request, registeredState *callbackState, userinfo *UserInfo, providerConfig *authTypes.OAuth2Provider) bool {
	usergroup := AppendAddToGroup(userinfo.Usergroup, providerConfig.AddToGroup)

	sessionID, err := RandString(32)
	if err != nil {
		log.WithError(err).Error("OAuth2 failed to generate session ID")
		writeOAuthClientError(w, http.StatusInternalServerError)
		return false
	}

	h.registerOAuthSession(sessionID, userinfo.Username, usergroup)

	log.WithFields(log.Fields{
		"sessionID": previewValue(sessionID),
		"username":  userinfo.Username,
		"usergroup": usergroup,
		"provider":  registeredState.providerName,
	}).Info("OAuth2 authentication successful, session registered")

	h.setOAuthCallbackCookie(w, r, h.cfg.GetOAuth2SessionCookieName(), sessionID)
	return true
}

func (h *OAuth2Handler) resolveOAuthUserinfo(w http.ResponseWriter, r *http.Request, registeredState *callbackState, code string) (*UserInfo, *authTypes.OAuth2Provider, bool) {
	providerConfig := h.cfg.OAuth2Providers[registeredState.providerName]
	userinfo, err := h.fetchOAuthUserInfo(r.Context(), registeredState, code, providerConfig)
	if err != nil {
		log.WithError(err).Error("OAuth2 failed to exchange authorization code")
		writeOAuthClientError(w, http.StatusBadRequest)
		return nil, nil, false
	}

	if !validateOAuthUsername(userinfo.Username) {
		log.WithFields(log.Fields{
			"provider": registeredState.providerName,
		}).Error("OAuth2 userinfo returned empty username")
		writeOAuthClientError(w, http.StatusBadRequest)
		return nil, nil, false
	}

	return userinfo, providerConfig, true
}

func (h *OAuth2Handler) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	log.Debug("OAuth2 callback received")

	registeredState, state, ok := h.checkOAuthCallbackCookie(w, r)
	if !ok {
		return
	}

	code := r.FormValue("code")
	if code == "" {
		log.Error("OAuth2 callback missing authorization code")
		writeOAuthClientError(w, http.StatusBadRequest)
		return
	}

	log.WithFields(log.Fields{
		"state": previewValue(state),
	}).Debug("OAuth2 authorization code received")

	userinfo, providerConfig, ok := h.resolveOAuthUserinfo(w, r, registeredState, code)
	if !ok {
		return
	}

	if !h.completeOAuthLogin(w, r, registeredState, userinfo, providerConfig) {
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

type UserInfo struct {
	Username  string
	Usergroup string
}

// GetUserInfo fetches user information from the userinfo endpoint.
// Exported for reuse by OIDC provider.
//
//gocyclo:ignore
func GetUserInfo(cfg *authTypes.Config, client *http.Client, provider *authTypes.OAuth2Provider) *UserInfo {
	return getUserInfo(cfg, client, provider)
}

//gocyclo:ignore
func getUserInfo(cfg *authTypes.Config, client *http.Client, provider *authTypes.OAuth2Provider) *UserInfo {
	ret := &UserInfo{}

	res, err := client.Get(provider.WhoamiUrl)

	if err != nil {
		log.Errorf("Failed to get user data: %v", err)
		return ret
	}

	if res.StatusCode != http.StatusOK {
		log.Errorf("Failed to get user data: %v", res.StatusCode)
		return ret
	}

	defer func() { _ = res.Body.Close() }()

	contents, err := io.ReadAll(res.Body)

	if err != nil {
		log.Errorf("Failed to read user data: %v", err)
		return ret
	}

	var userData map[string]any

	if cfg.InsecureAllowDumpOAuth2UserData {
		log.Debugf("OAuth2 User Data: %v+", string(contents))
	}

	err = json.Unmarshal([]byte(contents), &userData)

	if err != nil {
		log.Errorf("Failed to unmarshal user data: %v", err)

		return ret
	}

	ret.Username = getDataField(userData, provider.UsernameField)
	ret.Usergroup = getDataField(userData, provider.UserGroupField)

	return ret
}

func getDataField(data map[string]any, field string) string {
	if field == "" {
		return ""
	}

	val, ok := data[field]

	if !ok {
		log.Errorf("Failed to get field from user data: %v / %v", data, field)

		return ""
	}

	stringVal, ok := val.(string)

	if !ok {
		log.Errorf("Field %v is not a string: %v", field, val)
		return ""
	}

	return stringVal
}

func previewValue(value string) string {
	if len(value) > 8 {
		return value[:8] + "..."
	}
	return value
}

// AppendAddToGroup appends the AddToGroup value to the usergroup string if it's set.
// Groups are space-separated, and duplicates are avoided.
// Exported for reuse by OIDC provider.
func AppendAddToGroup(usergroup string, addToGroup string) string {
	return appendAddToGroup(usergroup, addToGroup)
}

// appendAddToGroup appends the AddToGroup value to the usergroup string if it's set.
// Groups are space-separated, and duplicates are avoided.
func appendAddToGroup(usergroup string, addToGroup string) string {
	if addToGroup == "" {
		return usergroup
	}

	// Parse existing groups
	groups := strings.Fields(usergroup)

	// Check if addToGroup is already in the list
	for _, group := range groups {
		if group == addToGroup {
			return usergroup // Already present, no need to add
		}
	}

	// Append the new group
	if usergroup == "" {
		return addToGroup
	}
	return usergroup + " " + addToGroup
}

func (h *OAuth2Handler) getOAuth2Cookie(context *authTypes.AuthCheckingContext) (*http.Cookie, []string, bool) {
	allCookies := context.Request.Cookies()
	cookieNames := make([]string, 0, len(allCookies))
	for _, c := range allCookies {
		cookieNames = append(cookieNames, c.Name)
	}
	log.WithFields(log.Fields{
		"path":        context.Request.URL.Path,
		"allCookies":  cookieNames,
		"cookieCount": len(allCookies),
	}).Debugf("OAuth2 checking for cookie, all cookies in request")

	cookie, err := context.Request.Cookie(context.Config.GetOAuth2SessionCookieName())
	if err != nil {
		log.WithFields(log.Fields{
			"error":       err,
			"provider":    "oauth2",
			"path":        context.Request.URL.Path,
			"allCookies":  cookieNames,
			"cookieCount": len(allCookies),
		}).Warnf("OAuth2 cookie not found in request")
		return nil, cookieNames, false
	}

	if cookie.Value == "" {
		log.WithFields(log.Fields{
			"provider": "oauth2",
			"path":     context.Request.URL.Path,
		}).Debugf("OAuth2 cookie has empty value")
		return nil, cookieNames, false
	}

	return cookie, cookieNames, true
}

func (h *OAuth2Handler) createAuthenticatedUserFromSession(authCtx *authTypes.AuthCheckingContext, cookieValue string, path string) *authTypes.AuthenticatedUser {
	cookieValuePreview := previewValue(cookieValue)
	log.WithFields(log.Fields{
		"cookieValue": cookieValuePreview,
		"path":        path,
	}).Debugf("OAuth2 cookie found, checking session storage")

	var sess *sessions.UserSession
	if authCtx.Sessions != nil {
		sess = authCtx.Sessions.GetSession("oauth2", cookieValue)
	} else {
		sess = sessions.GetUserSession("oauth2", cookieValue)
	}
	if sess == nil {
		sidPreview := previewValue(cookieValue)
		log.WithFields(log.Fields{
			"sid":      sidPreview,
			"provider": "oauth2",
			"path":     path,
		}).Warnf("OAuth2 session not found in session storage (stale session)")
		return nil
	}

	// Note: AddToGroup is already appended to sess.Usergroup when the session was registered
	// in HandleOAuthCallback. We use the stored value directly here.
	user := &authTypes.AuthenticatedUser{
		Username:      sess.Username,
		UsergroupLine: sess.Usergroup,
		Provider:      "oauth2",
		SID:           cookieValue,
	}

	log.WithFields(log.Fields{
		"username":  user.Username,
		"usergroup": user.UsergroupLine,
		"provider":  user.Provider,
		"path":      path,
	}).Infof("OAuth2 authentication successful from cookie")

	return user
}

func (h *OAuth2Handler) CheckUserFromOAuth2Cookie(authCtx *authTypes.AuthCheckingContext) *authTypes.AuthenticatedUser {
	cookie, _, ok := h.getOAuth2Cookie(authCtx)
	if !ok {
		return nil
	}

	return h.createAuthenticatedUserFromSession(authCtx, cookie.Value, authCtx.Request.URL.Path)
}
