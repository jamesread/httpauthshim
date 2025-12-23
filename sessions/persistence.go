package sessions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
)

// SessionPersistence defines the interface for persisting session data.
// Implementations can use any storage backend (file system, database, etc.).
type SessionPersistence interface {
	// Load loads session data from storage into the provided SessionStorage instance.
	// The dir and filename parameters identify where the data should be loaded from.
	// Returns an error if loading fails.
	Load(dir, filename string, storage *SessionStorage) error

	// Save saves session data from the provided SessionStorage instance to storage.
	// The dir and filename parameters identify where the data should be saved.
	// Returns an error if saving fails.
	Save(dir, filename string, storage *SessionStorage) error
	
	// RequiresFileLock returns true if this persistence backend requires file-based locking.
	// File-based backends (like YAML) should return true to enable cross-process locking.
	// Database backends should return false as they handle concurrency internally.
	RequiresFileLock() bool
}

// YAMLPersistence implements SessionPersistence using YAML files on the local filesystem.
// This is the default persistence implementation.
type YAMLPersistence struct{}

// NewYAMLPersistence creates a new YAML-based persistence backend.
func NewYAMLPersistence() *YAMLPersistence {
	return &YAMLPersistence{}
}

// RequiresFileLock returns true for YAML persistence as it uses file-based storage.
func (p *YAMLPersistence) RequiresFileLock() bool {
	return true
}

// tryLoadFromBackup attempts to load sessions from a backup file
func tryLoadFromBackup(backupPath string, storage *SessionStorage, p *YAMLPersistence, dir, filename string) error {
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{
		"backupPath": backupPath,
	}).Info("Attempting to recover sessions from backup file")

	if err := yaml.Unmarshal(backupData, storage); err != nil {
		logrus.WithError(err).Error("Backup file also corrupted, starting with empty storage")
		storage.ensureEmpty()
		return fmt.Errorf("both main and backup session files corrupted: %w", err)
	}

	// Backup loaded successfully - validate and optionally restore
	if err := storage.validateSessionData(); err != nil {
		logrus.WithError(err).Error("Backup file validation failed")
		storage.ensureEmpty()
		return fmt.Errorf("backup file validation failed: %w", err)
	}

	logrus.Info("Successfully recovered sessions from backup file")
	// Optionally restore backup to main file
	if err := p.Save(dir, filename, storage); err != nil {
		logrus.WithError(err).Warn("Failed to restore backup to main file")
	}
	return nil
}

// createBackupFile creates a backup of the current session data
func createBackupFile(filePath string, storage *SessionStorage) {
	backupPath := filePath + ".backup"
	backupData, err := yaml.Marshal(storage)
	if err != nil {
		return
	}

	if err := os.WriteFile(backupPath, backupData, 0600); err != nil {
		logrus.WithError(err).Warn("Failed to create backup file")
	} else {
		logrus.WithFields(logrus.Fields{
			"backupPath": backupPath,
		}).Debug("Created backup of session file")
	}
}

// Load loads sessions from a YAML file.
func (p *YAMLPersistence) Load(dir, filename string, storage *SessionStorage) error {
	// Clean up any orphaned temporary files from previous crashes
	cleanupOrphanedTempFiles(dir, filename)

	filePath := filepath.Join(dir, filename)
	data, err := os.ReadFile(filePath)
	if err != nil {
		logrus.WithError(err).Warn("Failed to read sessions file")
		storage.ensureEmpty()
		return err
	}

	// Try to unmarshal - if it fails, try backup file
	if err := yaml.Unmarshal(data, storage); err != nil {
		logrus.WithError(err).Warn("Failed to unmarshal sessions file, attempting backup recovery")
		backupPath := filePath + ".backup"
		if backupErr := tryLoadFromBackup(backupPath, storage, p, dir, filename); backupErr == nil {
			return nil
		}
		logrus.WithError(err).Warn("No backup file available for recovery")
		storage.ensureEmpty()
		return fmt.Errorf("failed to unmarshal sessions: %w", err)
	}

	// Main file loaded successfully - validate and create backup
	if err := storage.validateSessionData(); err != nil {
		logrus.WithError(err).Error("Session data validation failed")
		storage.ensureEmpty()
		return fmt.Errorf("session data validation failed: %w", err)
	}

	createBackupFile(filePath, storage)
	return nil
}

// ensureDirectoryWritable ensures the directory exists and is writable
func ensureDirectoryWritable(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat session directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("session directory path is not a directory: %s", dir)
	}

	return nil
}

// createBackupIfExists creates a backup of the main file if it exists
func createBackupIfExists(filePath string) {
	if _, err := os.Stat(filePath); err != nil {
		return // File doesn't exist, no backup needed
	}

	backupPath := filePath + ".backup"
	backupData, err := os.ReadFile(filePath)
	if err != nil {
		return // Can't read, skip backup
	}

	if err := os.WriteFile(backupPath, backupData, 0600); err != nil {
		logrus.WithError(err).Warn("Failed to create backup before write")
	}
}

// writeTempFile writes data to a temporary file with error handling
func writeTempFile(tempPath string, data []byte) error {
	requiredBytes := int64(len(data)) + 1024 // Add 1KB overhead

	err := os.WriteFile(tempPath, data, 0600)
	if err != nil {
		if isDiskSpaceError(err) {
			return fmt.Errorf("insufficient disk space to write session file (required: ~%d bytes): %w", requiredBytes, err)
		}
		return fmt.Errorf("failed to write temporary session file: %w", err)
	}

	return nil
}

// Save saves sessions to a YAML file using atomic writes.
// performAtomicWrite performs atomic file write with temp file and rename
func performAtomicWrite(tempPath, filePath string, data []byte) error {
	if err := writeTempFile(tempPath, data); err != nil {
		return err
	}

	// Atomic rename - if this fails, temp file remains but main file is unchanged
	if err := os.Rename(tempPath, filePath); err != nil {
		os.Remove(tempPath) // Try to clean up temp file
		return fmt.Errorf("failed to rename temporary session file: %w", err)
	}
	return nil
}

func (p *YAMLPersistence) Save(dir, filename string, storage *SessionStorage) (err error) {
	// Panic recovery to prevent file locks from being held indefinitely if Save panics
	defer func() {
		if r := recover(); r != nil {
			logrus.WithFields(logrus.Fields{
				"panic":    r,
				"dir":      dir,
				"filename": filename,
			}).Error("Panic in YAMLPersistence.Save()")
			err = fmt.Errorf("panic in persistence save: %v", r)
		}
	}()

	if err := ensureDirectoryWritable(dir); err != nil {
		return err
	}

	out, err := yaml.Marshal(storage)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	filePath := filepath.Join(dir, filename)
	createBackupIfExists(filePath)

	tempPath := filePath + ".tmp"
	return performAtomicWrite(tempPath, filePath, out)
}

// cleanupOrphanedTempFiles removes orphaned .tmp files from previous crashes
// This prevents accumulation of temporary files if the process crashes during writes
func cleanupOrphanedTempFiles(dir, filename string) {
	filePath := filepath.Join(dir, filename)
	tempPath := filePath + ".tmp"

	// Check if temp file exists
	if info, err := os.Stat(tempPath); err == nil {
		// Temp file exists - check if it's old (older than 1 hour suggests orphaned)
		age := time.Since(info.ModTime())
		if age > 1*time.Hour {
			logrus.WithFields(logrus.Fields{
				"tempPath": tempPath,
				"age":      age,
			}).Warn("Removing orphaned temporary session file from previous crash")
			if err := os.Remove(tempPath); err != nil {
				logrus.WithError(err).Warn("Failed to remove orphaned temporary file")
			}
		} else {
			// Temp file is recent - might be from concurrent write, leave it alone
			logrus.WithFields(logrus.Fields{
				"tempPath": tempPath,
				"age":      age,
			}).Debug("Found recent temporary file, leaving it (may be from concurrent write)")
		}
	}
}

// isDiskSpaceError checks if an error is related to disk space
func isDiskSpaceError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	// Check for common disk space error messages (case-insensitive)
	return strings.Contains(errStr, "no space") ||
		strings.Contains(errStr, "enospc") ||
		strings.Contains(errStr, "not enough space") ||
		strings.Contains(errStr, "disk full")
}
