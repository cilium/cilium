// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/lock"
)

type authMapCache struct {
	authmap           authMap
	cacheEntries      map[authKey]authInfo
	cacheEntriesMutex lock.RWMutex
}

func newAuthMapCache(authmap authMap) *authMapCache {
	return &authMapCache{
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
		return err
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
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					log.Debugf("auth: failed to delete auth entry with key %s: entry already deleted", k)
					continue
				}
				return fmt.Errorf("failed to delete auth entry from map: %w", err)
			}
			delete(r.cacheEntries, k)
		}
	}

	return nil
}

func (r *authMapCache) restoreCache() error {
	log.Debug("auth: starting cache restore")

	all, err := r.authmap.All()
	if err != nil {
		return fmt.Errorf("failed to load all auth map entries: %w", err)
	}
	for k, v := range all {
		r.cacheEntries[k] = v
	}

	log.Debugf("auth: restored %d entries", len(r.cacheEntries))
	return nil
}
