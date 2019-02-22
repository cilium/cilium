// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loader

import (
	"sync"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	once sync.Once

	// templateCache is the cache of pre-compiled datapaths.
	templateCache *objectCache
)

// Init initializes the datapath cache with base program hashes derived from
// the LocalNodeConfiguration.
func Init(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration) {
	once.Do(func() {
		templateCache = NewObjectCache(dp, nodeCfg)
	})
	templateCache.Update(nodeCfg)
}

// objectCache is a map from a hash of the datapath to the path on the
// filesystem where its corresponding BPF object file exists.
type objectCache struct {
	lock.Mutex
	datapath.Datapath

	workingDirectory string
	baseHash         *datapathHash
}

func newObjectCache(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration, workingDir string) *objectCache {
	oc := &objectCache{
		Datapath:         dp,
		workingDirectory: workingDir,
	}
	oc.Update(nodeCfg)
	return oc
}

// NewObjectCache creates a new cache for datapath objects, basing the hash
// upon the configuration of the datapath and the specified node configuration.
func NewObjectCache(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration) *objectCache {
	return newObjectCache(dp, nodeCfg, ".")
}

// Update may be called to update the base hash for configuration of datapath
// configuration that applies across the node.
func (o *objectCache) Update(nodeCfg *datapath.LocalNodeConfiguration) {
	newHash := hashDatapath(o.Datapath, nodeCfg, nil, nil)

	o.Lock()
	defer o.Unlock()
	o.baseHash = newHash
}

// EndpointHash hashes the specified endpoint configuration with the current
// datapath hash cache and returns the hash as string.
func EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	return templateCache.baseHash.sumEndpoint(templateCache, cfg, true)
}
