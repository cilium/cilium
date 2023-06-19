// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/lock"
)

type authMapCache struct {
	logger            logrus.FieldLogger
	authmap           authMap
	cacheEntries      map[authKey]authInfo
	cacheEntriesMutex lock.RWMutex
}

func newAuthMapCache(logger logrus.FieldLogger, authmap authMap) *authMapCache {
	return &authMapCache{
		logger:       logger,
		authmap:      authmap,
		cacheEntries: map[authKey]authInfo{},
	}
}

func (r *authMapCache) All() (map[authKey]authInfo, error) {
	r.cacheEntriesMutex.RLock()
	defer r.cacheEntriesMutex.RUnlock()

	result := make(map[authKey]authInfo)
	for k, v := range r.cacheEntries {
		result[k] = v
	}
	return maps.Clone(result), nil
}

func (r *authMapCache) Get(key authKey) (authInfo, error) {
	r.cacheEntriesMutex.RLock()
	defer r.cacheEntriesMutex.RUnlock()

	info, ok := r.cacheEntries[key]
	if !ok {
		return authInfo{}, fmt.Errorf("failed to get auth info for key: %s", key)
	}
	return info, nil
}

func (r *authMapCache) Update(key authKey, info authInfo) error {
	r.cacheEntriesMutex.Lock()
	defer r.cacheEntriesMutex.Unlock()

	if err := r.authmap.Update(key, info); err != nil {
		return err
	}

	r.cacheEntries[key] = info

	return nil
}

func (r *authMapCache) Delete(key authKey) error {
	r.cacheEntriesMutex.Lock()
	defer r.cacheEntriesMutex.Unlock()

	if err := r.authmap.Delete(key); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to delete auth entry from map: %w", err)
		}

		r.logger.
			WithField("key", key).
			Warning("Failed to delete already deleted auth entry")
	}

	delete(r.cacheEntries, key)

	return nil
}

func (r *authMapCache) DeleteIf(predicate func(key authKey, info authInfo) bool) error {
	r.cacheEntriesMutex.Lock()
	defer r.cacheEntriesMutex.Unlock()

	for k, v := range r.cacheEntries {
		if predicate(k, v) {
			// delete every entry individually to keep the cache in sync in case of an error
			if err := r.authmap.Delete(k); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					return fmt.Errorf("failed to delete auth entry from map: %w", err)
				}

				r.logger.
					WithField("key", k).
					Warning("Failed to delete already deleted auth entry")
			}
			delete(r.cacheEntries, k)
		}
	}

	return nil
}

func (r *authMapCache) restoreCache() error {
	r.logger.Debug("Starting cache restore")

	all, err := r.authmap.All()
	if err != nil {
		return fmt.Errorf("failed to load all auth map entries: %w", err)
	}
	for k, v := range all {
		r.cacheEntries[k] = v
	}

	r.logger.
		WithField("cached_entries", len(r.cacheEntries)).
		Debug("Restored entries")
	return nil
}
