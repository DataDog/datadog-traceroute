// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package tcp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_capHopTimeout(t *testing.T) {
	t.Run("no deadline on ctx returns the base timeout unchanged", func(t *testing.T) {
		got, err := capHopTimeout(context.Background(), 3*time.Second)
		require.NoError(t, err)
		assert.Equal(t, 3*time.Second, got)
	})

	t.Run("deadline further out than the base timeout leaves it unchanged", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()

		got, err := capHopTimeout(ctx, 3*time.Second)
		require.NoError(t, err)
		assert.Equal(t, 3*time.Second, got)
	})

	t.Run("deadline sooner than the base timeout caps it to the remaining time", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		got, err := capHopTimeout(ctx, 3*time.Second)
		require.NoError(t, err)
		assert.LessOrEqual(t, got, 50*time.Millisecond)
		assert.Greater(t, got, time.Duration(0))
	})

	t.Run("zero base timeout uses the context deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		got, err := capHopTimeout(ctx, 0)
		require.NoError(t, err)
		assert.LessOrEqual(t, got, 50*time.Millisecond)
		assert.Greater(t, got, time.Duration(0))
	})

	t.Run("already-expired deadline returns context.DeadlineExceeded", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), -time.Second)
		defer cancel()

		_, err := capHopTimeout(ctx, 3*time.Second)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})
}
