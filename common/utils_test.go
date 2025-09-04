package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConvertDurationToMs(t *testing.T) {
	assert.Equal(t, 1000.0, ConvertDurationToMs(1*time.Second))
	assert.Equal(t, 100.0, ConvertDurationToMs(100*time.Millisecond))
	assert.Equal(t, 123.456, ConvertDurationToMs(123456*time.Microsecond))
	assert.Equal(t, 0.0, ConvertDurationToMs(0))
}
