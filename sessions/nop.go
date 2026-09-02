package sessions

// NopPersistence is a SessionPersistence that never reads or writes files.
// Use it when the application owns sessions (for example database cookies)
// and must not use YAML file sessions.
type NopPersistence struct{}

// NewNopPersistence returns a no-op persistence backend.
func NewNopPersistence() *NopPersistence {
	return &NopPersistence{}
}

// Load does nothing.
func (*NopPersistence) Load(_, _ string, _ *SessionStorage) error {
	return nil
}

// Save does nothing.
func (*NopPersistence) Save(_, _ string, _ *SessionStorage) error {
	return nil
}

// RequiresFileLock reports that no file lock is needed.
func (*NopPersistence) RequiresFileLock() bool {
	return false
}
