// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cache

import (
	"errors"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		preSeedCache  func()
		callback      func() (string, error)
		wantValue     string
		wantErr       bool
		shouldCache   bool
		callbackCalls int // expected number of callback invocations
	}{
		{
			name: "cache miss - successful callback",
			key:  "test-key-1",
			callback: func() (string, error) {
				return "computed-value", nil
			},
			wantValue:     "computed-value",
			wantErr:       false,
			shouldCache:   true,
			callbackCalls: 1,
		},
		{
			name: "cache miss - callback returns error",
			key:  "test-key-2",
			callback: func() (string, error) {
				return "", errors.New("computation failed")
			},
			wantValue:     "",
			wantErr:       true,
			shouldCache:   false,
			callbackCalls: 1,
		},
		{
			name: "cache hit - callback not invoked",
			key:  "test-key-3",
			preSeedCache: func() {
				Cache.Set("test-key-3", "cached-value", cache.NoExpiration)
			},
			callback: func() (string, error) {
				t.Fatal("callback should not be called on cache hit")
				return "", nil
			},
			wantValue:     "cached-value",
			wantErr:       false,
			shouldCache:   true,
			callbackCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: Clear cache before each test
			Cache.Flush()

			// Pre-seed cache if needed
			if tt.preSeedCache != nil {
				tt.preSeedCache()
			}

			// Execute
			got, err := Get(tt.key, tt.callback)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantValue, got)

			// Verify caching behavior
			if tt.shouldCache {
				cached, found := Cache.Get(tt.key)
				assert.True(t, found, "value should be cached")
				assert.Equal(t, tt.wantValue, cached)
			} else {
				_, found := Cache.Get(tt.key)
				assert.False(t, found, "error result should not be cached")
			}
		})
	}
}

func TestGetWithExpiration(t *testing.T) {
	tests := []struct {
		name           string
		key            string
		expiration     time.Duration
		preSeedCache   func()
		callback       func() (int, error)
		wantValue      int
		wantErr        bool
		shouldCache    bool
		callbackCalls  int
		checkAfterWait *time.Duration // if set, wait this duration and verify cache state
	}{
		{
			name:       "cache miss - successful callback with no expiration",
			key:        "exp-key-1",
			expiration: cache.NoExpiration,
			callback: func() (int, error) {
				return 42, nil
			},
			wantValue:     42,
			wantErr:       false,
			shouldCache:   true,
			callbackCalls: 1,
		},
		{
			name:       "cache miss - callback returns error",
			key:        "exp-key-2",
			expiration: cache.NoExpiration,
			callback: func() (int, error) {
				return 0, errors.New("failed to compute")
			},
			wantValue:     0,
			wantErr:       true,
			shouldCache:   false,
			callbackCalls: 1,
		},
		{
			name:       "cache hit - callback not invoked",
			key:        "exp-key-3",
			expiration: cache.NoExpiration,
			preSeedCache: func() {
				Cache.Set("exp-key-3", 99, cache.NoExpiration)
			},
			callback: func() (int, error) {
				t.Fatal("callback should not be called on cache hit")
				return 0, nil
			},
			wantValue:     99,
			wantErr:       false,
			shouldCache:   true,
			callbackCalls: 0,
		},
		{
			name:       "cache with short expiration - expires after wait",
			key:        "exp-key-4",
			expiration: 100 * time.Millisecond,
			callback: func() (int, error) {
				return 123, nil
			},
			wantValue:      123,
			wantErr:        false,
			shouldCache:    true,
			callbackCalls:  1,
			checkAfterWait: ptrDuration(150 * time.Millisecond),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: Clear cache before each test
			Cache.Flush()

			// Pre-seed cache if needed
			if tt.preSeedCache != nil {
				tt.preSeedCache()
			}

			// Execute
			got, err := GetWithExpiration(tt.key, tt.callback, tt.expiration)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantValue, got)

			// Verify caching behavior
			if tt.shouldCache {
				cached, found := Cache.Get(tt.key)
				assert.True(t, found, "value should be cached")
				assert.Equal(t, tt.wantValue, cached)
			} else {
				_, found := Cache.Get(tt.key)
				assert.False(t, found, "error result should not be cached")
			}

			// Check expiration behavior if specified
			if tt.checkAfterWait != nil {
				time.Sleep(*tt.checkAfterWait)
				_, found := Cache.Get(tt.key)
				assert.False(t, found, "value should have expired from cache")
			}
		})
	}
}

func TestGet_DifferentTypes(t *testing.T) {
	Cache.Flush()

	t.Run("string type", func(t *testing.T) {
		result, err := Get("string-key", func() (string, error) {
			return "hello", nil
		})
		require.NoError(t, err)
		assert.Equal(t, "hello", result)
	})

	t.Run("int type", func(t *testing.T) {
		result, err := Get("int-key", func() (int, error) {
			return 42, nil
		})
		require.NoError(t, err)
		assert.Equal(t, 42, result)
	})

	t.Run("struct type", func(t *testing.T) {
		type testStruct struct {
			Name  string
			Value int
		}
		expected := testStruct{Name: "test", Value: 100}
		result, err := Get("struct-key", func() (testStruct, error) {
			return expected, nil
		})
		require.NoError(t, err)
		assert.Equal(t, expected, result)
	})
}

// Helper function to create pointer to duration
func ptrDuration(d time.Duration) *time.Duration {
	return &d
}
