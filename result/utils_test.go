package result

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBase64UUID(t *testing.T) {
	t.Run("non-empty", func(t *testing.T) {
		assert.NotEmpty(t, newBase64UUID())
	})

	t.Run("valid base64 RawURL encoding of 16 bytes", func(t *testing.T) {
		id := newBase64UUID()
		decoded, err := base64.RawURLEncoding.DecodeString(id)
		require.NoError(t, err)
		assert.Len(t, decoded, 16)
	})

	t.Run("unique across calls", func(t *testing.T) {
		seen := make(map[string]struct{})
		for range 100 {
			id := newBase64UUID()
			_, dup := seen[id]
			assert.False(t, dup, "duplicate id: %s", id)
			seen[id] = struct{}{}
		}
	})
}
