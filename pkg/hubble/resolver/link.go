// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
)

type LinkGetter struct {
	cache *link.LinkCache
}

func NewLinkGetter(linkCache *link.LinkCache) types.LinkGetter {
	return &LinkGetter{cache: linkCache}
}

func (g *LinkGetter) GetIfNameCached(ifIndex int) (string, bool) {
	if g.cache == nil {
		return "", false
	}
	return g.cache.GetIfNameCached(ifIndex)
}

func (g *LinkGetter) Name(ifIndex uint32) string {
	if g.cache == nil {
		return ""
	}
	return g.cache.Name(ifIndex)
}
