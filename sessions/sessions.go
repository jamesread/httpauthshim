package sessions

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
)

// Session management for user authentication
type UserSession struct {
	Username  string
	Usergroup string // Optional, used for OAuth2 sessions
	Expiry    int64
}

type SessionProvider struct {
	Sessions map[string]*UserSession
}

type SessionStorage struct {
	Providers map[string]*SessionProvider
	mu        sync.RWMutex        // Protects Providers map
	writeMu   sync.Mutex          // Serializes file writes to prevent race conditions
	
	// Persistence backend for loading and saving sessions
	persistence SessionPersistence // Pluggable persistence implementation
	
	// Async write management
	pendingWrite   atomic.Bool    // Indicates if a write is pending
	writeTimer     *time.Timer    // Timer for debounced writes
	writeTimerMu   sync.Mutex     // Protects writeTimer
	lastWriteDir   string         // Last write directory (for debounced writes)
	lastWriteFile  string         // Last write filename (for debounced writes)
	shutdownChan   chan struct{}  // Channel to signal shutdown
	cleanupTicker  *time.Ticker   // Ticker for periodic cleanup
	cleanupOnce    sync.Once      // Ensures cleanup goroutine starts only once
	
	// Error handling for async writes
	lastWriteError error           // Last error from async write
	lastWriteErrorMu sync.RWMutex // Protects lastWriteError
	
	// Retry mechanism for failed writes
	retryTimer     *time.Timer    // Timer for retrying failed writes
	retryTimerMu   sync.Mutex     // Protects retryTimer
	retryCount     int            // Number of consecutive retry attempts
	maxRetries     int            // Maximum number of retries before giving up
}

var (
	sessionStorage      *SessionStorage
	sessionStorageMutex sync.RWMutex
)

func init() {
	sessionStorage = &SessionStorage{
		Providers: make(map[string]*SessionProvider),
	}
}

// NewSessionStorage creates a new instance-based session storage.
// If persistence is nil, it defaults to YAMLPersistence.
func NewSessionStorage(persistence SessionPersistence) *SessionStorage {
	s := &SessionStorage{
		Providers:   make(map[string]*SessionProvider),
		shutdownChan: make(chan struct{}),
		maxRetries:  3, // Retry up to 3 times before giving up
	}
	
	// Use provided persistence or default to YAML
	if persistence == nil {
		s.persistence = NewYAMLPersistence()
	} else {
		s.persistence = persistence
	}
	
	// Start background cleanup goroutine
	s.startCleanupGoroutine()
	return s
}

// Shutdown stops background goroutines and performs final write
func (s *SessionStorage) Shutdown(dir, filename string) error {
	close(s.shutdownChan)
	
	s.writeTimerMu.Lock()
	if s.writeTimer != nil {
		s.writeTimer.Stop()
	}
	s.writeTimerMu.Unlock()
	
	s.retryTimerMu.Lock()
	if s.retryTimer != nil {
		s.retryTimer.Stop()
	}
	s.retryTimerMu.Unlock()
	
	if s.cleanupTicker != nil {
		s.cleanupTicker.Stop()
	}
	
	// Perform final synchronous write
	return s.saveSync(dir, filename)
}

// RegisterUserSession registers a user session (uses global storage for backward compatibility)
// DEPRECATED: Use SessionStorage.RegisterSession() instead for instance-based storage.
// cfg is used for file path, but we accept it as interface{} to avoid import cycle
func RegisterUserSession(cfg interface{ GetDir() string; GetSessionFileName() string }, provider string, sid string, username string, usergroup ...string) {
	sessionStorageMutex.Lock()
	defer sessionStorageMutex.Unlock()

	if sessionStorage.Providers[provider] == nil {
		sessionStorage.Providers[provider] = &SessionProvider{
			Sessions: make(map[string]*UserSession),
		}
	}

	ug := ""
	if len(usergroup) > 0 {
		ug = usergroup[0]
	}

	sessionStorage.Providers[provider].Sessions[sid] = &UserSession{
		Username:  username,
		Usergroup: ug,
		Expiry:    time.Now().Unix() + 31556952, // 1 year
	}

	saveUserSessions(cfg.GetDir(), cfg.GetSessionFileName())
}

// RegisterSession registers a user session on this storage instance
func (s *SessionStorage) RegisterSession(dir, filename string, provider string, sid string, username string, usergroup ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Providers[provider] == nil {
		s.Providers[provider] = &SessionProvider{
			Sessions: make(map[string]*UserSession),
		}
	}

	ug := ""
	if len(usergroup) > 0 {
		ug = usergroup[0]
	}

	s.Providers[provider].Sessions[sid] = &UserSession{
		Username:  username,
		Usergroup: ug,
		Expiry:    time.Now().Unix() + 31556952, // 1 year
	}

	s.saveAsync(dir, filename)
}

// GetUserSession retrieves a user session (uses global storage for backward compatibility)
// DEPRECATED: Use SessionStorage.GetSession() instead for instance-based storage.
func GetUserSession(provider string, sid string) *UserSession {
	sessionStorageMutex.Lock()
	defer sessionStorageMutex.Unlock()

	if sessionStorage.Providers[provider] == nil {
		return nil
	}

	session := sessionStorage.Providers[provider].Sessions[sid]
	if session == nil {
		return nil
	}

	if session.Expiry < time.Now().Unix() {
		delete(sessionStorage.Providers[provider].Sessions, sid)
		return nil
	}

	return session
}

// GetSession retrieves a user session from this storage instance
// deleteExpiredSession deletes an expired session with write lock
func (s *SessionStorage) deleteExpiredSession(provider, sid string, now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check after acquiring write lock (another goroutine might have deleted it)
	if s.Providers[provider] != nil && s.Providers[provider].Sessions != nil {
		if sess := s.Providers[provider].Sessions[sid]; sess != nil && sess.Expiry < now {
			delete(s.Providers[provider].Sessions, sid)
		}
	}
}

func (s *SessionStorage) GetSession(provider string, sid string) *UserSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Providers[provider] == nil || s.Providers[provider].Sessions == nil {
		return nil
	}

	session := s.Providers[provider].Sessions[sid]
	if session == nil {
		return nil
	}

	now := time.Now().Unix()
	if session.Expiry < now {
		// Release read lock before acquiring write lock
		s.mu.RUnlock()
		s.deleteExpiredSession(provider, sid, now)
		return nil
	}

	return session
}

// DeleteUserSession deletes a user session (uses global storage for backward compatibility)
// DEPRECATED: Use SessionStorage.DeleteSession() instead for instance-based storage.
func DeleteUserSession(cfg interface{ GetDir() string; GetSessionFileName() string }, provider string, sid string) {
	sessionStorageMutex.Lock()
	defer sessionStorageMutex.Unlock()

	if sessionStorage.Providers[provider] == nil {
		return
	}

	// Check if Sessions map exists before deleting
	if sessionStorage.Providers[provider].Sessions != nil {
		delete(sessionStorage.Providers[provider].Sessions, sid)
		saveUserSessions(cfg.GetDir(), cfg.GetSessionFileName())
	}
}

// DeleteSession deletes a user session from this storage instance
func (s *SessionStorage) DeleteSession(dir, filename string, provider string, sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Providers[provider] == nil {
		return
	}

	// Check if Sessions map exists before deleting
	if s.Providers[provider].Sessions != nil {
		delete(s.Providers[provider].Sessions, sid)
		s.saveAsync(dir, filename)
	}
}

// LoadUserSessions loads sessions from disk (uses global storage for backward compatibility)
// DEPRECATED: Use SessionStorage.Load() instead for instance-based storage.
func LoadUserSessions(cfg interface{ GetDir() string; GetSessionFileName() string }) {
	sessionStorageMutex.Lock()
	defer sessionStorageMutex.Unlock()

	filePath := filepath.Join(cfg.GetDir(), cfg.GetSessionFileName())
	data, err := os.ReadFile(filePath)
	if err != nil {
		logrus.WithError(err).Warn("Failed to read sessions.yaml file")
		ensureEmptySessionStorage()
		return
	}

	if err := yaml.Unmarshal(data, &sessionStorage); err != nil {
		logrus.WithError(err).Error("Failed to unmarshal sessions.yaml")
		ensureEmptySessionStorage()
		return
	}
}

// validateAndRemoveInvalidSession validates a single session and removes it if invalid
// validateSessionBasicFields validates basic session fields
func validateSessionBasicFields(providerName, sid string, session *UserSession) bool {
	if session == nil {
		logrus.WithFields(logrus.Fields{
			"provider": providerName,
			"sid":      sid,
		}).Warn("Found nil session, removing")
		return false
	}

	if session.Username == "" {
		logrus.WithFields(logrus.Fields{
			"provider": providerName,
			"sid":      sid,
		}).Warn("Found session with empty username, removing")
		return false
	}

	if sid == "" {
		logrus.WithFields(logrus.Fields{
			"provider": providerName,
		}).Warn("Found session with empty session ID, removing")
		return false
	}

	return true
}

// validateSessionExpiry validates session expiry time
func validateSessionExpiry(providerName, sid string, session *UserSession, now, maxFutureExpiry, maxPastExpiry int64) bool {
	if session.Expiry > maxFutureExpiry {
		logrus.WithFields(logrus.Fields{
			"provider": providerName,
			"sid":      sid,
			"expiry":   session.Expiry,
			"now":      now,
		}).Warn("Found session with expiry too far in future, removing")
		return false
	}

	if session.Expiry < maxPastExpiry {
		logrus.WithFields(logrus.Fields{
			"provider": providerName,
			"sid":      sid,
			"expiry":   session.Expiry,
			"now":      now,
		}).Debug("Found expired session, removing")
		return false
	}

	return true
}

func validateAndRemoveInvalidSession(providerName, sid string, session *UserSession, now, maxFutureExpiry, maxPastExpiry int64) bool {
	if !validateSessionBasicFields(providerName, sid, session) {
		return true
	}
	return !validateSessionExpiry(providerName, sid, session, now, maxFutureExpiry, maxPastExpiry)
}

// validateProviderSessions validates sessions for a single provider
func validateProviderSessions(providerName string, provider *SessionProvider, now, maxFutureExpiry, maxPastExpiry int64) int {
	if provider == nil || provider.Sessions == nil {
		return 0
	}

	invalidSessions := 0
	for sid, session := range provider.Sessions {
		if validateAndRemoveInvalidSession(providerName, sid, session, now, maxFutureExpiry, maxPastExpiry) {
			delete(provider.Sessions, sid)
			invalidSessions++
		}
	}

	return invalidSessions
}

// cleanupEmptyProvider removes a provider if it has no sessions
func cleanupEmptyProvider(providers map[string]*SessionProvider, providerName string, provider *SessionProvider) {
	if provider.Sessions != nil && len(provider.Sessions) == 0 {
		delete(providers, providerName)
	}
}

// validateSingleProvider validates a single provider and its sessions
func validateSingleProvider(providers map[string]*SessionProvider, providerName string, provider *SessionProvider, now, maxFutureExpiry, maxPastExpiry int64) int {
	if provider == nil {
		return 0
	}

	if providerName == "" {
		logrus.Warn("Found session provider with empty name, removing")
		delete(providers, providerName)
		return 0
	}

	count := validateProviderSessions(providerName, provider, now, maxFutureExpiry, maxPastExpiry)
	cleanupEmptyProvider(providers, providerName, provider)
	return count
}

// validateSessionData validates loaded session data for correctness and security
func (s *SessionStorage) validateSessionData() error {
	if s.Providers == nil {
		return nil // Empty is valid
	}

	now := time.Now().Unix()
	maxFutureExpiry := now + (10 * 365 * 24 * 60 * 60) // 10 years in the future
	maxPastExpiry := now - (1 * 365 * 24 * 60 * 60)   // 1 year in the past

	invalidSessions := 0
	for providerName, provider := range s.Providers {
		invalidSessions += validateSingleProvider(s.Providers, providerName, provider, now, maxFutureExpiry, maxPastExpiry)
	}

	if invalidSessions > 0 {
		logrus.WithFields(logrus.Fields{
			"invalidSessions": invalidSessions,
		}).Warn("Removed invalid sessions during validation")
	}

	return nil
}

// Load loads sessions from storage into this storage instance using the configured persistence backend.
func (s *SessionStorage) Load(dir, filename string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure persistence is set (should never be nil, but be safe)
	if s.persistence == nil {
		s.persistence = NewYAMLPersistence()
	}

	// Note: persistence.Load() may modify storage.Providers directly (e.g., YAML unmarshal),
	// so we must hold the lock. For slow backends (databases), consider implementing
	// async loading or loading into a temporary structure first.
	return s.persistence.Load(dir, filename, s)
}

func ensureEmptySessionStorage() {
	if sessionStorage == nil {
		sessionStorage = &SessionStorage{Providers: make(map[string]*SessionProvider)}
	}
	// Providers is initialized above, so this check is redundant but kept for safety
	if sessionStorage.Providers == nil {
		sessionStorage.Providers = make(map[string]*SessionProvider)
	}
}

func (s *SessionStorage) ensureEmpty() {
	// Providers is initialized in NewSessionStorage, so this check is redundant
	// but kept for safety in case Load is called on uninitialized storage
	if s.Providers == nil {
		s.Providers = make(map[string]*SessionProvider)
	}
}

var (
	globalWriteMu sync.Mutex // Serializes global session storage writes
	
	// fileWriteMutexes provides per-file mutexes to coordinate writes across multiple contexts
	// Keyed by file path (dir + filename)
	fileWriteMutexes      = make(map[string]*sync.Mutex)
	fileWriteMutexesMu    sync.Mutex // Protects fileWriteMutexes map
	fileMutexLastAccess   = make(map[string]time.Time) // Track last access time for cleanup
	maxFileMutexes        = 100                        // Maximum number of mutexes before cleanup
	fileMutexCleanupAge   = 1 * time.Hour              // Remove mutexes not accessed in this time
)

// cleanupUnusedFileMutexes removes mutexes that haven't been accessed recently.
// IMPORTANT: Caller must hold fileWriteMutexesMu.Lock() - this function does not acquire the lock.
func cleanupUnusedFileMutexes() {
	now := time.Now()
	cutoff := now.Add(-fileMutexCleanupAge)
	
	// Only clean up if we're significantly over the limit to avoid race conditions
	// We check lastAccess time, but a mutex could still be in use if a write is in progress.
	// By only cleaning up when we're well over the limit, we reduce the chance of
	// deleting a mutex that's about to be used.
	if len(fileWriteMutexes) <= maxFileMutexes {
		return // Not over limit, no cleanup needed
	}
	
	// Clean up mutexes that haven't been accessed in a while
	// Note: We can't check if a mutex is currently locked, so we rely on lastAccess time
	// and only clean up when we're significantly over the limit
	for path, lastAccess := range fileMutexLastAccess {
		if lastAccess.Before(cutoff) {
			delete(fileWriteMutexes, path)
			delete(fileMutexLastAccess, path)
			logrus.WithFields(logrus.Fields{
				"path":      path,
				"lastAccess": lastAccess,
			}).Debug("Cleaned up unused file write mutex")
		}
	}
}

// isProcessRunning checks if a process with the given PID is still running.
// Returns true if the process exists, false otherwise.
func isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	
	// Signal 0 doesn't actually send a signal, but checks if the process exists
	// On Unix systems, this returns an error if the process doesn't exist
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// checkLockFileAge checks if lock file is older than threshold
func checkLockFileAge(lockPath string) bool {
	info, err := os.Stat(lockPath)
	if err != nil {
		return true // File doesn't exist or can't be accessed
	}

	if time.Since(info.ModTime()) > 5*time.Minute {
		logrus.WithFields(logrus.Fields{
			"lockPath": lockPath,
			"age":      time.Since(info.ModTime()),
		}).Warn("Lock file is older than 5 minutes, considering stale")
		return true
	}
	return false
}

// checkLockFileProcess checks if the process associated with lock file exists
func checkLockFileProcess(lockPath string) bool {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return true // Can't read, consider stale
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return true // Invalid PID format, consider stale
	}

	if !isProcessRunning(pid) {
		logrus.WithFields(logrus.Fields{
			"lockPath": lockPath,
			"pid":      pid,
		}).Warn("Lock file PID is not running, lock is stale")
		return true
	}
	return false
}

// checkLockFileStale checks if a lock file is stale (process no longer running or too old).
// Returns true if stale and should be removed, false if valid.
func checkLockFileStale(lockPath string) bool {
	if checkLockFileAge(lockPath) {
		return true
	}
	return checkLockFileProcess(lockPath)
}

// retryLockAcquisition retries acquiring a lock file with exponential backoff
// tryAcquireLockWithStaleCheck attempts to acquire a lock, removing stale locks if found
func tryAcquireLockWithStaleCheck(lockPath string) (*os.File, error) {
	if checkLockFileStale(lockPath) {
		os.Remove(lockPath)
		// Retry immediately after removing stale lock
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err == nil {
			return lockFile, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("failed to acquire file lock: %w", err)
		}
	}
	return nil, nil
}

// tryAcquireLockOnce attempts to acquire a lock once
func tryAcquireLockOnce(lockPath string) (*os.File, error) {
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err == nil {
		return lockFile, nil
	}
	if !os.IsExist(err) {
		return nil, fmt.Errorf("failed to acquire file lock: %w", err)
	}
	return nil, nil // Lock exists, not an error
}

// tryAcquireLockWithRetry attempts to acquire lock with one retry attempt
func tryAcquireLockWithRetry(lockPath string) (*os.File, error) {
	if lockFile, err := tryAcquireLockOnce(lockPath); err != nil || lockFile != nil {
		return lockFile, err
	}
	// Check if lock became stale while waiting
	return tryAcquireLockWithStaleCheck(lockPath)
}

func retryLockAcquisition(lockPath string) (*os.File, error) {
	const maxRetries = 10
	const retryDelay = 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		time.Sleep(retryDelay)
		if lockFile, err := tryAcquireLockWithRetry(lockPath); err != nil || lockFile != nil {
			return lockFile, err
		}
	}
	return nil, fmt.Errorf("timeout waiting for file lock (another process may be writing)")
}

// handleExistingLock handles the case when a lock file already exists
func handleExistingLock(lockPath string) (*os.File, error) {
	if checkLockFileStale(lockPath) {
		// Stale lock - remove it and try again
		logrus.WithFields(logrus.Fields{
			"lockPath": lockPath,
		}).Warn("Removing stale lock file")
		os.Remove(lockPath)
		// Try once more after removing stale lock
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err == nil {
			return lockFile, nil
		}
		if os.IsExist(err) {
			// Another process got the lock between removal and creation - retry with backoff
			return retryLockAcquisition(lockPath)
		}
		return nil, fmt.Errorf("failed to create lock file after removing stale lock: %w", err)
	}
	// Lock is valid, another process is holding it - retry with backoff
	return retryLockAcquisition(lockPath)
}

// writeLockFilePID writes the process ID to the lock file for debugging and stale detection
func writeLockFilePID(lockFile *os.File, lockPath string) error {
	pid := fmt.Sprintf("%d\n", os.Getpid())
	if _, err := lockFile.WriteString(pid); err != nil {
		lockFile.Close()
		os.Remove(lockPath)
		return fmt.Errorf("failed to write PID to lock file: %w", err)
	}
	if err := lockFile.Sync(); err != nil {
		lockFile.Close()
		os.Remove(lockPath)
		return fmt.Errorf("failed to sync lock file: %w", err)
	}
	return nil
}

// createLockFile attempts to create a lock file, handling existing locks
func createLockFile(lockPath string) (*os.File, error) {
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err == nil {
		return lockFile, nil
	}
	if os.IsExist(err) {
		return handleExistingLock(lockPath)
	}
	return nil, fmt.Errorf("failed to create lock file: %w", err)
}

// acquireFileLock acquires an exclusive file lock for a session file.
// This prevents multiple processes from writing to the same file simultaneously.
// Returns the lock file handle and a cleanup function, or an error.
func acquireFileLock(dir, filename string) (*os.File, func(), error) {
	filePath := filepath.Join(dir, filename)
	lockPath := filePath + ".lock"

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	lockFile, err := createLockFile(lockPath)
	if err != nil {
		return nil, nil, err
	}

	// Write PID to lock file for debugging and stale detection
	if err := writeLockFilePID(lockFile, lockPath); err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		lockFile.Close()
		os.Remove(lockPath)
	}

	return lockFile, cleanup, nil
}

// getFileWriteMutex returns a mutex for a specific file path, creating it if needed
func getFileWriteMutex(dir, filename string) *sync.Mutex {
	filePath := filepath.Join(dir, filename)
	
	fileWriteMutexesMu.Lock()
	defer fileWriteMutexesMu.Unlock()
	
	// Update last access time
	fileMutexLastAccess[filePath] = time.Now()
	
	// Cleanup if map is getting too large (caller already holds the lock)
	if len(fileWriteMutexes) >= maxFileMutexes {
		cleanupUnusedFileMutexes() // Assumes lock is already held
	}
	
	if mu, exists := fileWriteMutexes[filePath]; exists {
		return mu
	}
	
	mu := &sync.Mutex{}
	fileWriteMutexes[filePath] = mu
	return mu
}

func saveUserSessions(dir, filename string) {
	// Serialize all file writes to prevent race conditions
	globalWriteMu.Lock()
	defer globalWriteMu.Unlock()

	// CRITICAL: Acquire read lock on sessionStorage before calling persistence.Save()
	// persistence.Save() reads sessionStorage.Providers (via yaml.Marshal), and we must prevent
	// concurrent modifications by RegisterUserSession/DeleteUserSession which hold write lock.
	sessionStorageMutex.RLock()
	defer sessionStorageMutex.RUnlock()

	// Use YAML persistence for global storage (backward compatibility)
	persistence := NewYAMLPersistence()
	if err := persistence.Save(dir, filename, sessionStorage); err != nil {
		logrus.WithError(err).Error("Failed to save session storage")
	}
}

// saveAsync schedules an async write with debouncing (500ms delay)
func (s *SessionStorage) saveAsync(dir, filename string) {
	s.writeTimerMu.Lock()
	defer s.writeTimerMu.Unlock()
	
	s.lastWriteDir = dir
	s.lastWriteFile = filename
	
	// Cancel existing timer if any
	if s.writeTimer != nil {
		s.writeTimer.Stop()
	}
	
	// Schedule write after 500ms of inactivity
	// Use stored dir/filename to ensure we write to the most recent path even if
	// saveAsync is called multiple times before the timer fires
	s.writeTimer = time.AfterFunc(500*time.Millisecond, func() {
		s.writeTimerMu.Lock()
		writeDir := s.lastWriteDir
		writeFile := s.lastWriteFile
		s.writeTimerMu.Unlock()
		
		if err := s.saveSync(writeDir, writeFile); err != nil {
			logrus.WithError(err).Error("Failed to save sessions asynchronously")
			s.lastWriteErrorMu.Lock()
			s.lastWriteError = err
			s.lastWriteErrorMu.Unlock()
			
			// Schedule retry if we haven't exceeded max retries
			s.scheduleRetry(writeDir, writeFile)
		} else {
			s.lastWriteErrorMu.Lock()
			s.lastWriteError = nil
			s.lastWriteErrorMu.Unlock()
			
			// Reset retry count on success
			s.retryTimerMu.Lock()
			s.retryCount = 0
			s.retryTimerMu.Unlock()
		}
		s.pendingWrite.Store(false)
	})
	
	s.pendingWrite.Store(true)
}

// scheduleRetry schedules a retry of a failed write with exponential backoff
func (s *SessionStorage) scheduleRetry(dir, filename string) {
	s.retryTimerMu.Lock()
	defer s.retryTimerMu.Unlock()
	
	// Check and increment retry count atomically within the lock
	currentRetryCount := s.retryCount
	if currentRetryCount >= s.maxRetries {
		logrus.WithFields(logrus.Fields{
			"retryCount": currentRetryCount,
			"maxRetries": s.maxRetries,
			"dir":        dir,
			"filename":   filename,
		}).Error("Max retries exceeded for session write, giving up")
		return
	}
	
	// Increment retry count atomically
	s.retryCount = currentRetryCount + 1
	newRetryCount := s.retryCount
	
	// Exponential backoff: 1s, 2s, 4s
	backoffDuration := time.Duration(1<<uint(newRetryCount-1)) * time.Second
	
	// Cancel existing retry timer if any
	if s.retryTimer != nil {
		s.retryTimer.Stop()
	}
	
	logrus.WithFields(logrus.Fields{
		"retryCount":     newRetryCount,
		"backoffSeconds": backoffDuration.Seconds(),
		"dir":            dir,
		"filename":       filename,
	}).Debug("Scheduling retry for failed session write")
	
	s.retryTimer = time.AfterFunc(backoffDuration, func() {
		if err := s.saveSync(dir, filename); err != nil {
			logrus.WithError(err).Error("Retry failed for session write")
			s.lastWriteErrorMu.Lock()
			s.lastWriteError = err
			s.lastWriteErrorMu.Unlock()
			
			// Schedule another retry (will check max retries again)
			s.scheduleRetry(dir, filename)
		} else {
			logrus.Debug("Session write retry succeeded")
			s.lastWriteErrorMu.Lock()
			s.lastWriteError = nil
			s.lastWriteErrorMu.Unlock()
			
			// Reset retry count on success (atomically)
			s.retryTimerMu.Lock()
			s.retryCount = 0
			s.retryTimerMu.Unlock()
		}
	})
}

// GetLastWriteError returns the last error from an async write operation.
// Returns nil if the last write succeeded or no write has occurred yet.
func (s *SessionStorage) GetLastWriteError() error {
	s.lastWriteErrorMu.RLock()
	defer s.lastWriteErrorMu.RUnlock()
	return s.lastWriteError
}

// saveSync performs synchronous write (used for final writes and immediate needs)
func (s *SessionStorage) saveSync(dir, filename string) error {
	// Also use instance mutex to prevent concurrent writes from same instance
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Ensure persistence is set (should never be nil, but be safe)
	if s.persistence == nil {
		s.persistence = NewYAMLPersistence()
	}

	// CRITICAL: Acquire read lock on Providers map before calling persistence.Save()
	// persistence.Save() reads storage.Providers (via yaml.Marshal), and we must prevent
	// concurrent modifications by RegisterSession/DeleteSession which hold write lock.
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Only apply file-based locking if the persistence backend requires it
	// Database backends handle concurrency internally and don't need file locks
	if s.persistence.RequiresFileLock() {
		// Get per-file mutex to coordinate writes across all contexts writing to the same file
		fileMu := getFileWriteMutex(dir, filename)
		fileMu.Lock()
		defer fileMu.Unlock()
		
		// Acquire file-level lock for cross-process coordination
		_, cleanup, err := acquireFileLock(dir, filename)
		if err != nil {
			return fmt.Errorf("failed to acquire file lock: %w", err)
		}
		defer cleanup() // cleanup() closes the lock file and removes the lock file
	}

	return s.persistence.Save(dir, filename, s)
}


// startCleanupGoroutine starts background goroutine to clean up expired sessions
func (s *SessionStorage) startCleanupGoroutine() {
	s.cleanupOnce.Do(func() {
		s.cleanupTicker = time.NewTicker(5 * time.Minute)
		go func() {
			for {
				select {
				case <-s.shutdownChan:
					return
				case <-s.cleanupTicker.C:
					s.cleanupExpiredSessions()
				}
			}
		}()
	})
}

// cleanupProviderSessions removes expired sessions from a single provider
// isSessionExpired checks if a session is expired
func isSessionExpired(session *UserSession, now int64) bool {
	if session == nil {
		return true
	}
	// Check expiry with a small buffer (1 second) to handle clock skew
	return session.Expiry <= now+1
}

func cleanupProviderSessions(providerName string, provider *SessionProvider, now int64) int {
	if provider == nil || provider.Sessions == nil {
		return 0
	}

	cleanedCount := 0
	for sid, session := range provider.Sessions {
		if isSessionExpired(session, now) {
			delete(provider.Sessions, sid)
			cleanedCount++
		}
	}

	return cleanedCount
}

// cleanupProvider removes nil providers or providers with nil sessions
func cleanupProvider(providers map[string]*SessionProvider, providerName string, provider *SessionProvider) bool {
	if provider == nil || provider.Sessions == nil {
		delete(providers, providerName)
		return true
	}
	return false
}

// cleanupProviderAndSessions cleans up a provider and its expired sessions
func cleanupProviderAndSessions(providers map[string]*SessionProvider, providerName string, provider *SessionProvider, now int64) int {
	if cleanupProvider(providers, providerName, provider) {
		return 0
	}

	count := cleanupProviderSessions(providerName, provider, now)
	// Remove empty providers
	if len(provider.Sessions) == 0 {
		delete(providers, providerName)
	}
	return count
}

// cleanupExpiredSessions removes expired sessions from memory
func (s *SessionStorage) cleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Handle nil Providers map (shouldn't happen, but be safe)
	if s.Providers == nil {
		return
	}

	now := time.Now().Unix()
	cleanedCount := 0
	for providerName, provider := range s.Providers {
		cleanedCount += cleanupProviderAndSessions(s.Providers, providerName, provider, now)
	}

	if cleanedCount > 0 {
		logrus.WithFields(logrus.Fields{
			"cleanedSessions": cleanedCount,
		}).Debugf("Cleaned up expired sessions")
	}
}
