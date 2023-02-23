// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package re provides a simple function to access compile regex objects for
// the FQDN subsystem.
package re

import (
	"errors"
	"fmt"
	"regexp"
	"sync/atomic"

	lru "github.com/golang/groupcache/lru"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdn/re")
)

// CompileRegex compiles a pattern p into a regex and returns the regex object.
// The regex object will be cached by an LRU. If p has already been compiled
// and cached, this function will return the cached regex object. If not
// already cached, it will compile p into a regex object and cache it in the
// LRU. This function will return an error if the LRU has not already been
// initialized.
func CompileRegex(p string) (*regexp.Regexp, error) {
	lru := regexCompileLRU.Load()
	if lru == nil {
		return nil, errors.New("FQDN regex compilation LRU not yet initialized")
	}
	lru.Lock()
	r, ok := lru.Get(p)
	lru.Unlock()
	if ok {
		return r.(*regexp.Regexp), nil
	}
	n, err := regexp.Compile(p)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %w", err)
	}
	lru.Lock()
	lru.Add(p, n)
	lru.Unlock()
	return n, nil
}

// InitRegexCompileLRU creates a new instance of the regex compilation LRU.
func InitRegexCompileLRU(size int) error {
	if size < 0 {
		return fmt.Errorf("failed to initialize FQDN regex compilation LRU due to invalid size %d", size)
	} else if size == 0 {
		log.Warnf(
			"FQDN regex compilation LRU size is unlimited, which can grow unbounded potentially consuming too much memory. Consider passing a maximum size via --%s.",
			option.FQDNRegexCompileLRUSize)
	}
	regexCompileLRU.Store(&RegexCompileLRU{
		Mutex: &lock.Mutex{},
		Cache: lru.New(size),
	})
	return nil
}

// regexCompileLRU is the singleton instance of the LRU that's shared
// throughout Cilium.
var regexCompileLRU atomic.Pointer[RegexCompileLRU]

// RegexCompileLRU is an LRU cache for storing compiled regex objects of FQDN
// names or patterns, used in CiliumNetworkPolicy or
// ClusterwideCiliumNetworkPolicy.
type RegexCompileLRU struct {
	// The lru package doesn't provide any concurrency guarantees so we must
	// provide our own locking.
	*lock.Mutex
	*lru.Cache
}
