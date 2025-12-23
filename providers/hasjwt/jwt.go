package hasjwt

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	authtypes "github.com/jamesread/httpauthshim/authpublic"
	log "github.com/sirupsen/logrus"
)

//nolint:unused // Kept for backward compatibility
func parseJwtToken(cfg *authtypes.Config, jwtString string) (*jwt.Token, error) {
	return parseJwtTokenCtx(context.Background(), cfg, jwtString)
}

func parseJwtTokenCtx(ctx context.Context, cfg *authtypes.Config, jwtString string) (*jwt.Token, error) {
	jwtCfg := cfg.Jwt

	if jwtCfg.CertsURL != "" {
		return parseJwtTokenWithRemoteKeyCtx(ctx, cfg, jwtString)
	}

	if jwtCfg.PubKeyPath != "" {
		return parseJwtTokenWithLocalKey(cfg, jwtString)
	}

	if jwtCfg.HmacSecret == "" {
		return nil, errors.New("no JWT authentication method configured")
	}

	return parseJwtTokenWithHMAC(cfg, jwtString)
}

//nolint:unused // Kept for backward compatibility
func getClaimsFromJwtToken(cfg *authtypes.Config, jwtString string) (jwt.MapClaims, error) {
	return getClaimsFromJwtTokenCtx(context.Background(), cfg, jwtString)
}

// getJwtAuthMethod returns a string describing the JWT authentication method used
func getJwtAuthMethod(jwtCfg authtypes.JwtConfig) string {
	if jwtCfg.CertsURL != "" {
		return fmt.Sprintf("JWKS (URL: %s)", jwtCfg.CertsURL)
	}
	if jwtCfg.PubKeyPath != "" {
		return fmt.Sprintf("local key (path: %s)", jwtCfg.PubKeyPath)
	}
	if jwtCfg.HmacSecret != "" {
		return "HMAC"
	}
	return "unknown"
}

// extractClaimsFromToken extracts claims from a validated JWT token
func extractClaimsFromToken(token *jwt.Token) (jwt.MapClaims, error) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("jwt token validation failed: token.Valid=%v, claims type=%T", token.Valid, token.Claims)
}

func getClaimsFromJwtTokenCtx(ctx context.Context, cfg *authtypes.Config, jwtString string) (jwt.MapClaims, error) {
	token, err := parseJwtTokenCtx(ctx, cfg, jwtString)
	if err != nil {
		method := getJwtAuthMethod(cfg.Jwt)
		log.WithFields(log.Fields{
			"method": method,
			"error":  err,
		}).Errorf("JWT parse failure using %s", method)
		return nil, fmt.Errorf("jwt parse failure using %s: %w", method, err)
	}

	return extractClaimsFromToken(token)
}

//nolint:unused // Kept for backward compatibility
func parseJwtTokenWithRemoteKey(cfg *authtypes.Config, jwtToken string) (*jwt.Token, error) {
	return parseJwtTokenWithRemoteKeyCtx(context.Background(), cfg, jwtToken)
}

// buildJwtParserOptions builds parser options from JWT config
func buildJwtParserOptions(jwtCfg authtypes.JwtConfig) []jwt.ParserOption {
	opts := []jwt.ParserOption{
		jwt.WithAudience(jwtCfg.Aud),
		jwt.WithLeeway(5 * time.Second),
	}
	if jwtCfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(jwtCfg.Issuer))
	}
	return opts
}

// checkContextCancelled checks if context is cancelled and returns error if so
func checkContextCancelled(ctx context.Context, operation string) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled during %s: %w", operation, ctx.Err())
	default:
		return nil
	}
}

// resetJwksState resets JWKS state to allow retry
func resetJwksState(state *jwtState) {
	state.jwksInitMu.Lock()
	state.jwksVerifier = nil
	state.jwksInitDone = false
	state.jwksInitMu.Unlock()
}


// initializeJwtState initializes JWT state and returns parser options
func initializeJwtState(ctx context.Context, cfg *authtypes.Config, state *jwtState) ([]jwt.ParserOption, error) {
	if err := initJwksCtx(ctx, cfg, state); err != nil {
		log.Errorf("jwt init JWKS failure: %v", err)
		return nil, err
	}

	if err := checkContextCancelled(ctx, "JWT parsing"); err != nil {
		return nil, err
	}

	return buildJwtParserOptions(cfg.Jwt), nil
}

// retryJwtParseWithRefresh retries JWT parsing after refreshing JWKS
func retryJwtParseWithRefresh(ctx context.Context, cfg *authtypes.Config, state *jwtState, jwtToken string, opts []jwt.ParserOption) (*jwt.Token, error) {
	if err := checkContextCancelled(ctx, "JWKS retry"); err != nil {
		return nil, err
	}

	resetJwksState(state)
	if retryErr := initJwksCtx(ctx, cfg, state); retryErr != nil {
		return nil, nil
	}
	// Retry parsing with refreshed keys
	return jwt.Parse(jwtToken, state.jwksVerifier.Keyfunc, opts...)
}

// shouldRetryJwtParse checks if JWT parse should be retried
func shouldRetryJwtParse(parseErr error, state *jwtState) bool {
	return parseErr != nil && state.jwksInitErr != nil
}

func parseJwtTokenWithRemoteKeyCtx(ctx context.Context, cfg *authtypes.Config, jwtToken string) (*jwt.Token, error) {
	state := getJwtState(cfg)
	opts, err := initializeJwtState(ctx, cfg, state)
	if err != nil {
		return nil, err
	}

	// Parse token - keyfunc.Keyfunc handles key refresh automatically
	token, parseErr := jwt.Parse(jwtToken, state.jwksVerifier.Keyfunc, opts...)

	// If parsing fails and we had a previous init error, try to reinitialize JWKS
	if shouldRetryJwtParse(parseErr, state) {
		log.WithFields(log.Fields{
			"certsURL": cfg.Jwt.CertsURL,
			"error":    parseErr,
		}).Debugf("JWT parse failed, attempting to reinitialize JWKS")

		if retryToken, retryErr := retryJwtParseWithRefresh(ctx, cfg, state, jwtToken, opts); retryErr == nil && retryToken != nil {
			return retryToken, nil
		}
	}

	return token, parseErr
}

// jwtState stores JWT verification state for a specific configuration
type jwtState struct {
	// For remote JWKS
	jwksVerifier keyfunc.Keyfunc
	jwksInitErr  error
	jwksInitMu   sync.Mutex // Protects JWKS initialization (allows retry on failure)
	jwksInitDone bool        // Tracks if initialization was attempted

	// For local public key
	pubKeyBytes   []byte
	pubKey        *rsa.PublicKey
	loadedKeyPath string
	loadedKeyMtime time.Time // Track file modification time for change detection
	localKeyMutex sync.RWMutex
	localKeyErr   error
	
	// Track last access time for cleanup
	lastAccess time.Time
	accessMu  sync.RWMutex
}

var (
	// jwtStateMap stores JWT state per config (keyed by hash of JWT config fields)
	// This avoids memory leaks from pointer addresses and prevents wrong state reuse
	jwtStateMap      = make(map[string]*jwtState)
	jwtStateMapMu    sync.RWMutex
	maxJwtStateMapSize = 100 // Maximum number of JWT states to prevent unbounded growth
	
	// Cleanup management
	cleanupTicker  *time.Ticker
	cleanupTickerMu sync.Mutex
	cleanupStarted  bool
)

// getJwtConfigKey creates a unique key from JWT config fields that affect state
// This ensures same config values share state, and different configs don't interfere
func getJwtConfigKey(cfg *authtypes.Config) string {
	jwtCfg := cfg.Jwt
	// Create hash from fields that determine JWT verification state
	keyData := fmt.Sprintf("%s|%s|%s", jwtCfg.CertsURL, jwtCfg.PubKeyPath, jwtCfg.HmacSecret)
	hash := sha256.Sum256([]byte(keyData))
	return hex.EncodeToString(hash[:])
}

func getJwtState(cfg *authtypes.Config) *jwtState {
	key := getJwtConfigKey(cfg)

	jwtStateMapMu.RLock()
	state, exists := jwtStateMap[key]
	jwtStateMapMu.RUnlock()

	if exists {
		// Update last access time
		state.accessMu.Lock()
		state.lastAccess = time.Now()
		state.accessMu.Unlock()
		return state
	}

	// Create new state
	jwtStateMapMu.Lock()
	defer jwtStateMapMu.Unlock()

	// Double-check after acquiring write lock
	if state, exists := jwtStateMap[key]; exists {
		state.accessMu.Lock()
		state.lastAccess = time.Now()
		state.accessMu.Unlock()
		return state
	}

	// Check if we've exceeded the maximum size and clean up if needed
	// Note: We already hold jwtStateMapMu.Lock(), so use the locked versions
	if len(jwtStateMap) >= maxJwtStateMapSize {
		// Clean up states older than 1 hour (lock already held)
		cleanupUnusedJwtStatesLocked(1 * time.Hour)
		// If still too large, remove oldest entries (lock already held)
		if len(jwtStateMap) >= maxJwtStateMapSize {
			evictOldestJwtStates(maxJwtStateMapSize / 2)
		}
	}

	state = &jwtState{
		lastAccess: time.Now(),
	}
	jwtStateMap[key] = state
	return state
}

// cleanupJwtStateResources cleans up resources held by a JWT state before deletion
func cleanupJwtStateResources(state *jwtState) {
	// Clean up keyfunc resources if it implements io.Closer
	// keyfunc.Keyfunc may hold HTTP clients that need to be closed
	if state.jwksVerifier != nil {
		// Check if jwksVerifier implements io.Closer (for resource cleanup)
		if closer, ok := state.jwksVerifier.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				log.WithError(err).Debug("Error closing JWT keyfunc verifier (non-fatal)")
			}
		}
		state.jwksVerifier = nil
	}
}

// evictOldestJwtStates removes the oldest entries from the JWT state map
// until the map size is reduced to targetSize.
// IMPORTANT: Caller must hold jwtStateMapMu.Lock() - this function does not acquire the lock.
// collectJwtStateEntries collects all JWT state entries with their access times
func collectJwtStateEntries() []struct {
	key       string
	lastAccess time.Time
} {
	type stateEntry struct {
		key        string
		lastAccess time.Time
	}
	
	entries := make([]stateEntry, 0, len(jwtStateMap))
	for key, state := range jwtStateMap {
		state.accessMu.RLock()
		lastAccess := state.lastAccess
		state.accessMu.RUnlock()
		entries = append(entries, stateEntry{key: key, lastAccess: lastAccess})
	}
	
	// Sort by last access time (oldest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastAccess.Before(entries[j].lastAccess)
	})
	
	// Convert to return type
	result := make([]struct {
		key        string
		lastAccess time.Time
	}, len(entries))
	for i, e := range entries {
		result[i].key = e.key
		result[i].lastAccess = e.lastAccess
	}
	return result
}

// removeOldestJwtStates removes the oldest JWT states up to target size
func removeOldestJwtStates(entries []struct {
	key        string
	lastAccess time.Time
}, targetSize int) {
	toRemove := len(jwtStateMap) - targetSize
	if toRemove <= 0 {
		return
	}
	
	for i := 0; i < toRemove && i < len(entries); i++ {
		key := entries[i].key
		if state, exists := jwtStateMap[key]; exists {
			cleanupJwtStateResources(state)
			delete(jwtStateMap, key)
		}
	}
}

func evictOldestJwtStates(targetSize int) {
	entries := collectJwtStateEntries()
	removeOldestJwtStates(entries, targetSize)
}

// cleanupUnusedJwtStatesLocked removes JWT states that haven't been accessed recently.
// IMPORTANT: Caller must hold jwtStateMapMu.Lock() - this function does not acquire the lock.
func cleanupUnusedJwtStatesLocked(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	for key, state := range jwtStateMap {
		state.accessMu.RLock()
		lastAccess := state.lastAccess
		state.accessMu.RUnlock()
		
		if lastAccess.Before(cutoff) {
			cleanupJwtStateResources(state)
			delete(jwtStateMap, key)
		}
	}
}

// CleanupUnusedJwtStates removes JWT states that haven't been accessed recently.
// This should be called periodically to prevent unbounded memory growth.
// States not accessed within maxAge are removed.
func CleanupUnusedJwtStates(maxAge time.Duration) {
	jwtStateMapMu.Lock()
	defer jwtStateMapMu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, state := range jwtStateMap {
		state.accessMu.RLock()
		lastAccess := state.lastAccess
		state.accessMu.RUnlock()
		
		if lastAccess.Before(cutoff) {
			cleanupJwtStateResources(state)
			delete(jwtStateMap, key)
		}
	}
}

// GetJwtStateMapSize returns the current number of JWT states in the map.
// Useful for monitoring and debugging.
func GetJwtStateMapSize() int {
	jwtStateMapMu.RLock()
	defer jwtStateMapMu.RUnlock()
	return len(jwtStateMap)
}

// performJwtStateCleanup performs a single cleanup cycle with panic recovery
func performJwtStateCleanup() {
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{
				"panic": r,
			}).Errorf("Panic recovered in JWT cleanup goroutine, continuing")
		}
	}()

	// Skip cleanup if map is empty (optimization)
	jwtStateMapMu.RLock()
	size := len(jwtStateMap)
	jwtStateMapMu.RUnlock()

	if size == 0 {
		return // No states to clean up
	}

	// Clean up states not accessed in the last 2 hours
	CleanupUnusedJwtStates(2 * time.Hour)

	// Also check if we're over the size limit and evict oldest if needed
	jwtStateMapMu.RLock()
	size = len(jwtStateMap)
	jwtStateMapMu.RUnlock()

	if size >= maxJwtStateMapSize {
		evictOldestJwtStates(maxJwtStateMapSize / 2)
	}
}

// startJwtStateCleanup starts a background goroutine to periodically clean up unused JWT states.
// This prevents unbounded memory growth when contexts are created and destroyed.
// The cleanup runs every 30 minutes and removes states not accessed in the last 2 hours.
func startJwtStateCleanup() {
	cleanupTickerMu.Lock()
	defer cleanupTickerMu.Unlock()

	if cleanupStarted {
		return
	}

	cleanupStarted = true
	cleanupTicker = time.NewTicker(30 * time.Minute)

	go func() {
		for range cleanupTicker.C {
			performJwtStateCleanup()
		}
	}()
}

func init() {
	// Start automatic cleanup on package initialization
	startJwtStateCleanup()
}

//nolint:unused // Kept for backward compatibility
func initJwks(cfg *authtypes.Config, state *jwtState) error {
	return initJwksCtx(context.Background(), cfg, state)
}

// checkJwksInitialized checks if JWKS is already initialized
func checkJwksInitialized(state *jwtState) bool {
	return state.jwksVerifier != nil && state.jwksInitErr == nil
}

// initializeJwksVerifier initializes the JWKS verifier with context timeout
func initializeJwksVerifier(ctx context.Context, certsURL string) (keyfunc.Keyfunc, error) {
	if err := checkContextCancelled(ctx, "JWKS initialization"); err != nil {
		return nil, err
	}
	return keyfunc.NewDefaultCtx(ctx, []string{certsURL})
}

// handleJwksInitError handles JWKS initialization error
func handleJwksInitError(state *jwtState, certsURL string, err error) error {
	state.jwksInitDone = true
	state.jwksInitErr = err
	log.WithFields(log.Fields{
		"certsURL": certsURL,
		"error":    err,
	}).Errorf("Init JWKS Failure (will retry on next request)")
	return err
}

// handleJwksInitSuccess handles successful JWKS initialization
func handleJwksInitSuccess(state *jwtState, verifier keyfunc.Keyfunc, certsURL string) {
	state.jwksVerifier = verifier
	state.jwksInitErr = nil
	log.WithFields(log.Fields{
		"certsURL": certsURL,
	}).Debugf("JWKS initialized successfully (keyfunc handles automatic refresh)")
}

// logJwksRetry logs a JWKS retry attempt
func logJwksRetry(certsURL string, err error) {
	log.WithFields(log.Fields{
		"certsURL": certsURL,
		"error":    err,
	}).Debugf("Retrying JWKS initialization after previous failure")
}

// performJwksInitialization performs the actual JWKS initialization
func performJwksInitialization(reqCtx context.Context, certsURL string, state *jwtState) error {
	// Use request context with timeout, respecting cancellation
	ctx, cancel := context.WithTimeout(reqCtx, 30*time.Second)
	defer cancel()

	verifier, err := initializeJwksVerifier(ctx, certsURL)
	if err != nil {
		return handleJwksInitError(state, certsURL, err)
	}

	handleJwksInitSuccess(state, verifier, certsURL)
	return nil
}

func initJwksCtx(reqCtx context.Context, cfg *authtypes.Config, state *jwtState) error {
	if cfg.Jwt.CertsURL == "" {
		return nil
	}

	state.jwksInitMu.Lock()
	defer state.jwksInitMu.Unlock()

	// If already initialized successfully, return
	if checkJwksInitialized(state) {
		return nil
	}

	// If initialization failed before, allow retry (for key rotation scenarios)
	if state.jwksInitErr != nil && state.jwksInitDone {
		logJwksRetry(cfg.Jwt.CertsURL, state.jwksInitErr)
	}

	return performJwksInitialization(reqCtx, cfg.Jwt.CertsURL, state)
}

func loadPublicKeyFromFile(keyPath string, state *jwtState) error {
	// Read file with timeout to prevent hanging on network filesystems
	keyBytes, err := readFileWithTimeout(keyPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("couldn't read public key from file %s: %w", keyPath, err)
	}

	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
	if err != nil {
		return fmt.Errorf("error parsing public key object (from %s): %w", keyPath, err)
	}

	// Get file modification time for change detection
	var mtime time.Time
	if stat, err := os.Stat(keyPath); err == nil {
		mtime = stat.ModTime()
	}

	state.pubKeyBytes = keyBytes
	state.pubKey = parsedKey
	state.loadedKeyPath = keyPath
	state.loadedKeyMtime = mtime
	state.localKeyErr = nil
	
	log.WithFields(log.Fields{
		"keyPath": keyPath,
		"mtime":   mtime,
	}).Debugf("JWT public key loaded from file")
	
	return nil
}

// readFileWithTimeout reads a file with a timeout to prevent hanging on slow filesystems
func readFileWithTimeout(filePath string, timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	
	resultChan := make(chan result, 1)
	go func() {
		data, err := os.ReadFile(filePath)
		resultChan <- result{data: data, err: err}
	}()
	
	select {
	case res := <-resultChan:
		return res.data, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout reading file %s after %v", filePath, timeout)
	}
}

func isKeyLoadedForPath(keyPath string, state *jwtState) bool {
	if state.pubKeyBytes == nil || state.loadedKeyPath != keyPath {
		return false
	}
	
	// Check if file modification time has changed
	if stat, err := os.Stat(keyPath); err == nil {
		if !stat.ModTime().Equal(state.loadedKeyMtime) {
			// File has been modified, need to reload
			return false
		}
	}
	
	return true
}

func readLocalPublicKeyWithLock(keyPath string, state *jwtState) error {
	state.localKeyMutex.RLock()
	alreadyLoaded := isKeyLoadedForPath(keyPath, state)
	state.localKeyMutex.RUnlock()

	if alreadyLoaded {
		return nil
	}

	state.localKeyMutex.Lock()
	defer state.localKeyMutex.Unlock()

	if isKeyLoadedForPath(keyPath, state) {
		return nil
	}

	state.localKeyErr = loadPublicKeyFromFile(keyPath, state)
	return state.localKeyErr
}

func readLocalPublicKey(cfg *authtypes.Config) error {
	if cfg.Jwt.PubKeyPath == "" {
		return errors.New("no JWT public key path configured")
	}
	state := getJwtState(cfg)
	return readLocalPublicKeyWithLock(cfg.Jwt.PubKeyPath, state)
}

func parseJwtTokenWithLocalKey(cfg *authtypes.Config, jwtString string) (*jwt.Token, error) {
	state := getJwtState(cfg)
	err := readLocalPublicKey(cfg)

	if err != nil {
		return nil, err
	}

	return jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("parseJwt expected token algorithm RSA but got: %v", token.Header["alg"])
		}

		return state.pubKey, nil
	})
}

// Hash-based Message Authentication Code
func parseJwtTokenWithHMAC(cfg *authtypes.Config, jwtString string) (*jwt.Token, error) {
	return jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parseJwt expected token algorithm HMAC but got: %v", token.Header["alg"])
		}

		return []byte(cfg.Jwt.HmacSecret), nil
	})
}

// getRequiredClaim fetches a required claim from JWT claims and validates it is present and non-empty.
// Returns an error if the claim is missing or empty.
func getRequiredClaim(claims jwt.MapClaims, claimKey string, claimName string) (string, error) {
	if claimKey == "" {
		return "", fmt.Errorf("required claim key for %s is not configured", claimName)
	}

	val, ok := claims[claimKey]
	if !ok {
		return "", fmt.Errorf("required JWT claim '%s' (key: '%s') is missing", claimName, claimKey)
	}

	claimValue := strings.TrimSpace(fmt.Sprintf("%s", val))
	if claimValue == "" {
		return "", fmt.Errorf("required JWT claim '%s' (key: '%s') is present but empty", claimName, claimKey)
	}

	return claimValue, nil
}

func CheckUserFromJwtCookie(authCtx *authtypes.AuthCheckingContext) *authtypes.AuthenticatedUser {
	// Check if context is cancelled (handle nil context for backward compatibility)
	if authCtx.Context != nil {
		select {
		case <-authCtx.Context.Done():
			log.Debugf("JWT cookie check cancelled: %v", authCtx.Context.Err())
			return nil
		default:
		}
	}

	cookieName := authCtx.Config.Jwt.CookieName
	cookie, err := authCtx.Request.Cookie(cookieName)

	if err != nil {
		log.Debugf("jwt cookie check %v name: %v", err, cookieName)
		return nil
	}

	ctx := authCtx.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return parseJwtCtx(ctx, authCtx.Config, cookie.Value)
}

func CheckUserFromJwtHeader(authCtx *authtypes.AuthCheckingContext) *authtypes.AuthenticatedUser {
	// Check if context is cancelled (handle nil context for backward compatibility)
	if authCtx.Context != nil {
		select {
		case <-authCtx.Context.Done():
			log.Debugf("JWT header check cancelled: %v", authCtx.Context.Err())
			return nil
		default:
		}
	}

	header := authCtx.Request.Header.Get(authCtx.Config.Jwt.Header)
	if header == "" {
		return nil
	}

	token := strings.TrimPrefix(header, "Bearer ")
	token = strings.TrimSpace(token)

	ctx := authCtx.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return parseJwtCtx(ctx, authCtx.Config, token)
}

func parseJwt(cfg *authtypes.Config, token string) *authtypes.AuthenticatedUser { //nolint:unused // Kept for backward compatibility
	return parseJwtCtx(context.Background(), cfg, token)
}

func parseJwtCtx(ctx context.Context, cfg *authtypes.Config, token string) *authtypes.AuthenticatedUser {
	claims, err := getClaimsFromJwtTokenCtx(ctx, cfg, token)

	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"tokenPreview": func() string {
				if len(token) > 20 {
					return token[:20] + "..."
				}
				return token
			}(),
		}).Warnf("JWT claim extraction error")
		return nil
	}

	jwtCfg := cfg.Jwt
	if jwtCfg.InsecureAllowDumpJwtClaims {
		log.Debugf("JWT Claims %+v", claims)
	}

	// Validate required claims before constructing AuthenticatedUser
	username, err := getRequiredClaim(claims, jwtCfg.ClaimUsername, "username")
	if err != nil {
		log.Warnf("jwt validation error: %v", err)
		return nil
	}

	user := &authtypes.AuthenticatedUser{
		Username:      username,
		UsergroupLine: parseGroupClaim(jwtCfg.ClaimUserGroup, claims),
		Provider:      "jwt",
	}

	return user
}

func parseGroupClaim(groupClaim string, claims jwt.MapClaims) string {
	usergroup := ""
	if val, ok := claims[groupClaim]; ok {
		if array, ok := val.([]interface{}); ok {
			groups := make([]string, len(array))
			for i, v := range array {
				groups[i] = fmt.Sprintf("%s", v)
			}
			usergroup = strings.Join(groups, " ")
		} else {
			usergroup = fmt.Sprintf("%s", val)
		}
	}
	return usergroup
}
