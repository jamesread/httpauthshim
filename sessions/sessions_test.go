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

func TestRegisterSessionUsesAbsoluteTimeout(t *testing.T) {
	s := NewSessionStorage(NewYAMLPersistence())
	s.ConfigureTimeouts(DefaultIdleTimeoutSeconds, 3600)
	dir := t.TempDir()

	before := time.Now().Unix()
	s.RegisterSession(dir, "sessions.yaml", "local", "sid", "alice", "admin")
	after := time.Now().Unix()

	s.mu.RLock()
	sess := s.Providers["local"].Sessions["sid"]
	s.mu.RUnlock()

	assert.GreaterOrEqual(t, sess.Expiry, before+3600)
	assert.LessOrEqual(t, sess.Expiry, after+3600)
	assert.GreaterOrEqual(t, sess.LastActivity, before)
}

func TestGetSessionIdleTimeout(t *testing.T) {
	s := NewSessionStorage(NewYAMLPersistence())
	s.ConfigureTimeouts(1, DefaultAbsoluteTimeoutSeconds) // 1 second idle
	dir := t.TempDir()

	s.RegisterSession(dir, "sessions.yaml", "local", "idle-sid", "alice", "admin")

	s.mu.Lock()
	s.Providers["local"].Sessions["idle-sid"].LastActivity = time.Now().Unix() - 5
	s.mu.Unlock()

	assert.Nil(t, s.GetSession("local", "idle-sid"))
}

func TestGetSessionIdleDisabled(t *testing.T) {
	s := NewSessionStorage(NewYAMLPersistence())
	s.ConfigureTimeouts(0, DefaultAbsoluteTimeoutSeconds) // idle disabled
	dir := t.TempDir()

	s.RegisterSession(dir, "sessions.yaml", "local", "sid", "alice", "admin")

	s.mu.Lock()
	s.Providers["local"].Sessions["sid"].LastActivity = time.Now().Unix() - 3600
	s.mu.Unlock()

	assert.NotNil(t, s.GetSession("local", "sid"))
}

func TestDefaultTimeoutsMatchOWASP(t *testing.T) {
	assert.Equal(t, 30*60, DefaultIdleTimeoutSeconds)
	assert.Equal(t, 8*60*60, DefaultAbsoluteTimeoutSeconds)
}
