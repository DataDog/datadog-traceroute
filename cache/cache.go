// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package cache implements a cache
package cache

import (
	"time"

	"github.com/patrickmn/go-cache"
)

const (
	defaultExpire = 5 * time.Minute
	defaultPurge  = 30 * time.Second
)

// Cache provides an in-memory key:value store similar to memcached
var Cache = cache.New(defaultExpire, defaultPurge)

// Get returns the value for 'key'.
//
// cache hit:
//
//	pull the value from the cache and returns it.
//
// cache miss:
//
//	call 'cb' function to get a new value. If the callback doesn't return an error the returned value is
//	cached with no expiration date and returned.
func Get[T any](key string, cb func() (T, error)) (T, error) {
	return GetWithExpiration[T](key, cb, cache.NoExpiration)
}

// GetWithExpiration returns the value for 'key'.
//
// cache hit:
//
//	pull the value from the cache and returns it.
//
// cache miss:
//
//	call 'cb' function to get a new value. If the callback doesn't return an error the returned value is
//	cached with the given expire duration and returned.
func GetWithExpiration[T any](key string, cb func() (T, error), expire time.Duration) (T, error) {
	if x, found := Cache.Get(key); found {
		return x.(T), nil
	}

	res, err := cb()
	// We don't cache errors
	if err == nil {
		Cache.Set(key, res, expire)
	}
	return res, err
}
