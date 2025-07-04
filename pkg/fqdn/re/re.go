// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package re provides a simple function to access compile regex objects for
// the FQDN subsystem.
package re

import (
	"fmt"
	"log/slog"
	"regexp"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

// CompileRegex compiles a pattern p into a regex and returns the regex object.
// The regex object will be cached by an LRU. If p has already been compiled
// and cached, this function will return the cached regex object. If not
// already cached, it will compile p into a regex object and cache it in the
// LRU. This function will return an error if the LRU has not already been
// initialized.
func CompileRegex(p string) (*regexp.Regexp, error) {
	r, ok := regexCompileLRU.cache.Get(p)
	if ok {
		return r, nil
	}
	n, err := regexp.Compile(p)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %w", err)
	}
	regexCompileLRU.cache.Add(p, n)
	return n, nil
}

func Resize(logger *slog.Logger, size uint) {
	if size == 0 {
		// effectively unlimited
		size = 16_000_000
		logger.Warn(fmt.Sprintf(
			"FQDN regex compilation LRU size is unlimited, which can grow unbounded potentially consuming too much memory. Consider passing a maximum size via --%s.",
			option.FQDNRegexCompileLRUSize,
		))
	}
	regexCompileLRU.cache.Resize(int(size))
}

func newRegexCache(size uint) *RegexCompileLRU {
	c, err := lru.New[string, *regexp.Regexp](int(size))
	if err != nil {
		panic(err) // unreachable, only for zero size
	}
	return &RegexCompileLRU{
		cache: c,
	}
}

// regexCompileLRU is the singleton instance of the LRU that's shared
// throughout Cilium.
var regexCompileLRU = newRegexCache(defaults.FQDNRegexCompileLRUSize)

// RegexCompileLRU is an LRU cache for storing compiled regex objects of FQDN
// names or patterns, used in CiliumNetworkPolicy or
// ClusterwideCiliumNetworkPolicy.
type RegexCompileLRU struct {
	cache *lru.Cache[string, *regexp.Regexp]
}
