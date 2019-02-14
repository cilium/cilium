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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var (
	once sync.Once

	// elfCache is the cache of pre-compiled datapaths.
	elfCache ObjectCache
)

// Init initializes the datapath cache with base program hashes derived from
// the LocalNodeConfiguration.
func Init(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration) {
	once.Do(func() {
		elfCache = NewObjectCache(dp, nodeCfg)
		elf.IgnoreSymbolPrefixes([]string{
			"2/",             // Calls within the endpoint
			"HOST_IP",        // Global
			"ROUTER_IP",      // Global
			"cilium_ct",      // All CT maps, including local
			"cilium_events",  // Global
			"cilium_ipcache", // Global
			"cilium_lb",      // Global
			"cilium_lxc",     // Global
			"cilium_metrics", // Global
			"cilium_proxy",   // Global
			"cilium_tunnel",  // Global
			"from-container", // Prog name
		})
	})
	elfCache.Update(nodeCfg)
}

// buildChan is closed when a build is completed, successful or not.
type buildChan chan struct{}

func (b buildChan) wait(ctx context.Context) error {
	select {
	case <-b:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// ObjectCache is a map from a hash of the datapath to the path on the
// filesystem where its corresponding BPF object file exists.
type ObjectCache struct {
	lock.Mutex
	datapath.Datapath

	workingDirectory string
	baseHash         *Hash

	// toPath maps a hash to the filesystem path of the corresponding object.
	toPath map[string]string

	// exists maps a hash to a channel that will be closed when the
	// corresponding datapath object has been successfully compiled.
	exists map[string]buildChan
}

func newObjectCache(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration, workingDir string) ObjectCache {
	oc := ObjectCache{
		Datapath:         dp,
		workingDirectory: workingDir,
		toPath:           make(map[string]string),
		exists:           make(map[string]buildChan),
	}
	oc.Update(nodeCfg)
	return oc
}

func NewObjectCache(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration) ObjectCache {
	return newObjectCache(dp, nodeCfg, ".")
}

// Update may be called to update the base hash for configuration of datapath
// configuration that applies across the node.
func (o *ObjectCache) Update(nodeCfg *datapath.LocalNodeConfiguration) {
	newHash := HashDatapath(o.Datapath, nodeCfg, nil, nil)

	o.Lock()
	defer o.Unlock()
	o.baseHash = newHash
}

// serialize finds the channel that serializes builds against the same hash.
// Returns the channel and whether or not the caller needs to compile the
// datapath for this hash.
func (o *ObjectCache) serialize(hash string) (c buildChan, found bool) {
	o.Lock()
	defer o.Unlock()

	c, compiled := o.exists[hash]
	if !compiled {
		c = make(buildChan, 0)
		o.exists[hash] = c
	}
	return c, compiled
}

func (o *ObjectCache) lookup(hash string) (string, bool) {
	o.Lock()
	defer o.Unlock()
	path, exists := o.toPath[hash]
	return path, exists
}

func (o *ObjectCache) insert(hash, objectPath string) {
	o.Lock()
	defer o.Unlock()
	o.toPath[hash] = objectPath
}

// build attempts to compile and cache a datapath template object file
// corresponding to the specified endpoint configuration. If successful,
// returns the filesystem path to the object file, otherwise an error.
func (o *ObjectCache) build(ctx context.Context, cfg *templateCfg, hash string) (string, bool, error) {
	templatePath := filepath.Join(o.workingDirectory, "templates", hash)
	headerPath := filepath.Join(templatePath, common.CHeaderFileName)
	objectPath := filepath.Join(templatePath, "bpf_lxc.o")

	if err := os.MkdirAll(templatePath, defaults.StateDirRights); err != nil {
		return "", false, err
	}

	f, err := os.Create(headerPath)
	if err != nil {
		return "", false, &os.PathError{
			Op:   "failed to open template header for writing",
			Path: headerPath,
			Err:  err,
		}
	}

	if err = o.Datapath.WriteEndpointConfig(f, cfg, true); err != nil {
		return "", false, &os.PathError{
			Op:   "failed to write template header",
			Path: headerPath,
			Err:  err,
		}
	}

	err = CompileEndpoint(ctx, templatePath)
	if err != nil {
		return "", false, err
	}

	log.WithFields(logrus.Fields{
		logfields.Path: objectPath,
	}).Info("Compiled new BPF template")

	o.insert(hash, objectPath)
	return objectPath, true, nil
}

// FetchOrCompile attempts to fetch the path to the datapath object
// corresponding to the provided endpoint configuration, or if this
// configuration is not yet compiled, compiles it. It will block if multiple
// threads attempt to concurrently FetchOrCompile a template binary for the
// same set of EndpointConfiguration.
//
// Returns the path to the compiled template datapath object and whether the
// object was compiled, or an error.
func (o *ObjectCache) FetchOrCompile(ctx context.Context, cfg datapath.EndpointConfiguration) (string, bool, error) {
	hash := o.baseHash.Copy().SumEndpoint(cfg)

	// Look up the channel that serializes attempts to compile this cfg.
	c, compiled := o.serialize(hash)
	if !compiled {
		defer close(c)
		templateCfg := wrap(cfg)
		return o.build(ctx, templateCfg, hash)
	}

	// Wait on the channel until the build completes.
	err := c.wait(ctx)
	if err != nil {
		return "", false, fmt.Errorf("context cancelled while waiting for template compilation: %s", err)
	}

	// Fetch the result of the compilation.
	path, ok := o.lookup(hash)
	if !ok {
		return "", false, fmt.Errorf("peer compilation for this template failed")
	}

	return path, false, nil
}

// Flush the object cache.
//
// TODO: Implement, plumb somewhere
func (o *ObjectCache) Flush() {
}

// HashEndpoint hashes the specified endpoint configuration with the current
// datapath hash cache and returns the hash as string.
func HashEndpoint(cfg datapath.EndpointConfiguration) string {
	return elfCache.baseHash.Copy().SumEndpoint(cfg)
}
