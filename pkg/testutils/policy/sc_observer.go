// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testpolicy

import (
	"sync"

	"github.com/cilium/cilium/pkg/identity"
)

type SelectorCacheUpdater interface {
	UpdateIdentities(added, deleted identity.IdentityMapOld, wg *sync.WaitGroup) bool
}

type SelectorCacheObserver struct {
	Cache SelectorCacheUpdater
}

func (o SelectorCacheObserver) LocalEndpointIdentityAdded(id *identity.Identity) {
	o.Cache.UpdateIdentities(identity.IdentityMapOld{id.ID: id.LabelArray}, nil, &sync.WaitGroup{})
}

func (o SelectorCacheObserver) LocalEndpointIdentityRemoved(id *identity.Identity) {
	o.Cache.UpdateIdentities(nil, identity.IdentityMapOld{id.ID: id.LabelArray}, &sync.WaitGroup{})
}
