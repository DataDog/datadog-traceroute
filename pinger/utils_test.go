package pinger

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_convertRttsAsFloat(t *testing.T) {
	rtts := []time.Duration{
		11234 * time.Microsecond,
		5223 * time.Microsecond,
	}
	expected := []float32{
		11.234,
		5.223,
	}
	assert.Equal(t, expected, convertRttsAsFloat(rtts))
}
