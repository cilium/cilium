// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"strconv"

	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
)

// LinkGetter implements types.LinkGetter using the datapath link cache.
type LinkGetter struct {
	cache *link.LinkCache
}

func NewLinkGetter(linkCache *link.LinkCache) types.LinkGetter {
	return &LinkGetter{cache: linkCache}
}

// GetIfNameCached implements types.LinkGetter.
func (g *LinkGetter) GetIfNameCached(ifIndex int) (string, bool) {
	if g.cache == nil {
		return "", false
	}
	return g.cache.GetIfNameCached(ifIndex)
}

// Name implements types.LinkGetter.
func (g *LinkGetter) Name(ifIndex uint32) string {
	if g.cache == nil {
		return strconv.FormatUint(uint64(ifIndex), 10)
	}
	return g.cache.Name(ifIndex)
}
