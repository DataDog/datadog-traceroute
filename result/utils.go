package result

import (
	"encoding/base64"

	"github.com/google/uuid"
)

// encode UUID with base64 for shorter UUID
func newBase64UUID() string {
	id := uuid.New()
	return base64.RawURLEncoding.EncodeToString(id[:])
}
