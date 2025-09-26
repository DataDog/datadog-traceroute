// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const (
	defaultExpire      = 5 * time.Minute
	defaultPurge       = 30 * time.Second
	defaultCacheFolder = "datadog-traceroute-db"
)

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
func Get(key string, cb func() ([]byte, error)) ([]byte, error) {
	return GetWithExpiration(key, cb, 0)
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
func GetWithExpiration(key string, cb func() ([]byte, error), expire time.Duration) ([]byte, error) {

	// Open the Badger database located in the /tmp/badger directory.
	// It is created if it doesn't exist.
	cacheFolder := filepath.Join(os.TempDir(), defaultCacheFolder)
	db, err := badger.Open(badger.DefaultOptions(cacheFolder))
	if err != nil {
		return nil, err
	}

	defer db.Close()

	var myIP []byte
	err = db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {

			res, err := cb()

			//ip, err := doGetIP()
			//fmt.Printf("Get IP: %s\n", ip.String())
			if err != nil {
				return err
			}
			myIP = res

			e := badger.NewEntry([]byte(key), res).WithTTL(expire)
			err = txn.SetEntry(e)
			return err
		} else {
			fmt.Printf("[CACHE] ExpiresAt: %d\n", item.ExpiresAt())

			countdown := time.Unix(int64(item.ExpiresAt()), 0).Sub(time.Now())
			fmt.Printf("[CACHE] ExpiresAt time: %f\n", countdown.Seconds())
			var valCopy []byte
			err = item.Value(func(val []byte) error {
				// This func with val would only be called if item.Value encounters no error.

				// Copying or parsing val is valid.
				valCopy = append([]byte{}, val...)

				myIP = valCopy

				return nil
			})
			return err
		}
	})
	if err != nil {
		return nil, err
	}

	//if x, found := Cache.Get(key); found {
	//	return x.(T), nil
	//}
	//
	//res, err := cb()
	//// We don't cache errors
	//if err == nil {
	//	Cache.Set(key, res, expire)
	//}
	return myIP, err
}
