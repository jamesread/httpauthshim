package sessions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNopPersistence(t *testing.T) {
	p := NewNopPersistence()
	s := NewSessionStorage(p)

	require.NoError(t, p.Load("/unused", "sessions.yaml", s))
	require.NoError(t, p.Save("/unused", "sessions.yaml", s))
	assert.False(t, p.RequiresFileLock())
}
