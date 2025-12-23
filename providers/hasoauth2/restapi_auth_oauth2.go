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
	"sync"
	"time"

	authTypes "github.com/jamesread/httpauthshim/authpublic"
	"github.com/jamesread/httpauthshim/sessions"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type OAuth2Handler struct {
	cfg                 *authTypes.Config
	sessionStorage      *sessions.SessionStorage // Instance-based session storage
	callbackStates      map[string]*callbackState // Temporary state for OAuth callback flow
	callbackStatesMutex sync.RWMutex              // Protects callbackStates map
	registeredProviders map[string]*oauth2.Config
	shutdownChan        chan struct{} // Channel to signal shutdown
	shutdownOnce        sync.Once    // Ensures shutdown is called only once
	
	// Cached HTTP clients per provider (keyed by provider name)
	httpClients      map[string]*http.Client
	httpClientsMu    sync.RWMutex // Protects httpClients map
	
	// Cached cert bundles per provider (keyed by cert bundle path)
	certBundles      map[string]*x509.CertPool
	certBundlesMu    sync.RWMutex // Protects certBundles map
	certBundleMtimes map[string]time.Time // Track file modification times for cache invalidation
}

// NewOAuth2Handler creates a new OAuth2 handler with instance-based session storage.
// If sessionStorage is nil, it will fall back to global session storage (deprecated).
func NewOAuth2Handler(cfg *authTypes.Config, sessionStorage *sessions.SessionStorage) *OAuth2Handler {
	h := &OAuth2Handler{
		cfg:            cfg,
		sessionStorage: sessionStorage,
		shutdownChan:   make(chan struct{}),
	}

	h.callbackStates = make(map[string]*callbackState)
	h.registeredProviders = make(map[string]*oauth2.Config)
	h.httpClients = make(map[string]*http.Client)
	h.certBundles = make(map[string]*x509.CertPool)
	h.certBundleMtimes = make(map[string]time.Time)

	log.Infof("OAuth2 providers: %v", cfg.OAuth2Providers)

	for providerName, providerConfig := range cfg.OAuth2Providers {
		completeProviderConfig(providerName, providerConfig)

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

		log.Debugf("Dumping newly registered provider: %v = %+v", providerName, providerConfig)
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
	expiresAt      time.Time // Expiration time for this state (single-use, temporary)
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
		Secure:   r.TLS != nil,
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode, // Allow cookie to be sent on redirects from OAuth provider
	}

	http.SetCookie(w, cookie)
	cookieValuePreview := value
	if len(value) > 8 {
		cookieValuePreview = value[:8] + "..."
	}
	log.WithFields(log.Fields{
		"cookieName":  name,
		"cookieValue": cookieValuePreview,
		"secure":      cookie.Secure,
		"sameSite":    cookie.SameSite,
		"maxAge":      cookie.MaxAge,
	}).Infof("OAuth2 cookie set")
}

func (h *OAuth2Handler) HandleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	log.Infof("OAuth2 login request: %v", r.URL.Query())

	state, err := randString(16)

	log.Infof("OAuth2 state: %v", state)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	providerName := r.URL.Query().Get("provider")
	provider, err := h.getOAuth2Config(providerName)

	if err != nil {
		log.Errorf("Failed to get provider config: %v %v", providerName, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Store state with expiration (15 minutes TTL for OAuth callback)
	h.callbackStatesMutex.Lock()
	h.callbackStates[state] = &callbackState{
		providerConfig: provider,
		providerName:   providerName,
		expiresAt:      time.Now().Add(15 * time.Minute),
	}
	h.callbackStatesMutex.Unlock()

	h.setOAuthCallbackCookie(w, r, h.cfg.GetOAuth2SessionCookieName(), state)

	loginUrl := provider.AuthCodeURL(state)

	log.Infof("OAuth2 state: %v mapped to provider %v (found: %v), now redirecting to %v", state, providerName, provider != nil, loginUrl)

	http.Redirect(w, r, loginUrl, http.StatusFound)
}

func (h *OAuth2Handler) validateStateMatch(queryState, cookieState string) bool {
	return queryState == cookieState
}

func (h *OAuth2Handler) checkOAuthCallbackCookie(w http.ResponseWriter, r *http.Request) (*callbackState, string, bool) {
	cookie, err := r.Cookie(h.cfg.GetOAuth2SessionCookieName())
	if err != nil {
		log.WithFields(log.Fields{
			"error":      err,
			"allCookies": r.Cookies(),
		}).Errorf("Failed to get state cookie")
		http.Error(w, "State not found", http.StatusBadRequest)
		return nil, "", false
	}

	state := cookie.Value
	queryState := r.URL.Query().Get("state")

	log.WithFields(log.Fields{
		"cookieState": state,
		"queryState":  queryState,
		"statesMatch": state == queryState,
	}).Debugf("OAuth2 callback state validation")

	if !h.validateStateMatch(queryState, state) {
		log.WithFields(log.Fields{
			"queryState":  queryState,
			"cookieState": state,
		}).Errorf("State mismatch")
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return nil, state, false
	}

	// Check state exists and hasn't expired
	h.callbackStatesMutex.Lock()
	callbackState, ok := h.callbackStates[state]
	if !ok {
		h.callbackStatesMutex.Unlock()
		log.WithFields(log.Fields{
			"state":               state,
			"callbackStatesCount": len(h.callbackStates),
		}).Errorf("State not found in server")
		http.Error(w, "State not found in server", http.StatusBadRequest)
		return nil, state, false
	}

	// Check if state has expired
	if time.Now().After(callbackState.expiresAt) {
		delete(h.callbackStates, state)
		h.callbackStatesMutex.Unlock()
		log.WithFields(log.Fields{
			"state":     state,
			"expiresAt": callbackState.expiresAt,
		}).Errorf("State has expired")
		http.Error(w, "State has expired", http.StatusBadRequest)
		return nil, state, false
	}

	// Delete state immediately after validation to prevent replay attacks (single-use)
	delete(h.callbackStates, state)
	h.callbackStatesMutex.Unlock()

	log.WithFields(log.Fields{
		"state":    state,
		"provider": callbackState.providerName,
	}).Debugf("OAuth2 callback state validated successfully and marked as used")

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

func (h *OAuth2Handler) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	log.Infof("OAuth2 Callback received")

	registeredState, state, ok := h.checkOAuthCallbackCookie(w, r)

	if !ok {
		return
	}

	code := r.FormValue("code")

	log.WithFields(log.Fields{
		"state":      state,
		"token-code": code,
	}).Debug("OAuth2 Token Code")

	providerConfig := h.cfg.OAuth2Providers[registeredState.providerName]

	// Get or create cached HTTP client for this provider
	baseClient := h.getOrCreateHttpClient(registeredState.providerName, providerConfig)

	// Use request context to respect cancellation and timeouts
	ctx := r.Context()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, baseClient)

	tok, err := registeredState.providerConfig.Exchange(ctx, code)

	if err != nil {
		log.Errorf("Failed to exchange code: %v", err)
		http.Error(w, "Failed to exchange code", http.StatusBadRequest)
		return
	}

	// Create user info client with OAuth2 transport, reusing base transport
	baseTransport := baseClient.Transport.(*http.Transport)
	userInfoClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: registeredState.providerConfig.TokenSource(ctx, tok),
			Base:   baseTransport,
		},
		Timeout: baseClient.Timeout,
	}

	userinfo := getUserInfo(h.cfg, userInfoClient, h.cfg.OAuth2Providers[registeredState.providerName])

	// Generate a fresh cryptographically secure session ID (do not reuse the state)
	sessionID, err := randString(32)
	if err != nil {
		log.Errorf("Failed to generate session ID: %v", err)
		http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
		return
	}

	// Register the user session with the new session ID (not the state)
	// Use instance-based session storage if available, otherwise fall back to global (deprecated)
	if h.sessionStorage != nil {
		h.sessionStorage.RegisterSession(h.cfg.GetDir(), h.cfg.GetSessionFileName(), "oauth2", sessionID, userinfo.Username, userinfo.Usergroup)
	} else {
		sessions.RegisterUserSession(h.cfg, "oauth2", sessionID, userinfo.Username, userinfo.Usergroup)
	}

	// State was already deleted in checkOAuthCallbackCookie to prevent replay

	log.WithFields(log.Fields{
		"state":     state,
		"sessionID": sessionID,
		"username":  userinfo.Username,
		"usergroup": userinfo.Usergroup,
		"provider":  registeredState.providerName,
	}).Infof("OAuth2 authentication successful, session registered")

	// Set the cookie with the new session ID (not the state)
	// This ensures the cookie persists for the full session duration
	h.setOAuthCallbackCookie(w, r, h.cfg.GetOAuth2SessionCookieName(), sessionID)

	http.Redirect(w, r, "/", http.StatusFound)
}

type UserInfo struct {
	Username  string
	Usergroup string
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

	defer res.Body.Close()

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
