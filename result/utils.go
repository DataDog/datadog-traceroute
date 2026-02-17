package result

import (
	"encoding/base64"

	"github.com/google/uuid"
)

func newBase64UUID() string {
	id := uuid.New()
	return base64.RawURLEncoding.EncodeToString(id[:])
}
