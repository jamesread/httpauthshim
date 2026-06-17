package sessions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetSessionExpiredDoesNotPanic(t *testing.T) {
	s := NewSessionStorage(NewYAMLPersistence())
	dir := t.TempDir()

	s.RegisterSession(dir, "sessions.yaml", "local", "expired-sid", "alice", "admin")

	s.mu.Lock()
	s.Providers["local"].Sessions["expired-sid"].Expiry = time.Now().Unix() - 1
	s.mu.Unlock()

	assert.NotPanics(t, func() {
		got := s.GetSession("local", "expired-sid")
		assert.Nil(t, got)
	})

	got := s.GetSession("local", "expired-sid")
	assert.Nil(t, got)
}

func TestGetSessionValidReturnsSession(t *testing.T) {
	s := NewSessionStorage(NewYAMLPersistence())
	dir := t.TempDir()

	s.RegisterSession(dir, "sessions.yaml", "local", "valid-sid", "alice", "admin")

	got := s.GetSession("local", "valid-sid")
	assert.NotNil(t, got)
	assert.Equal(t, "alice", got.Username)
	assert.Equal(t, "admin", got.Usergroup)
}
