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
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/serializer"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

var (
	once sync.Once

	// templateCache is the cache of pre-compiled datapaths.
	templateCache            *objectCache
	templateWatcherQueueSize = 10

	ignoredELFPrefixes = []string{
		"2/",                   // Calls within the endpoint
		"HOST_IP",              // Global
		"ROUTER_IP",            // Global
		"SNAT_IPV6_EXTERNAL",   // Global
		"cilium_ct",            // All CT maps, including local
		"cilium_encrypt_state", // Global
		"cilium_events",        // Global
		"cilium_ipcache",       // Global
		"cilium_lb",            // Global
		"cilium_lxc",           // Global
		"cilium_metrics",       // Global
		"cilium_policy",        // Global
		"cilium_proxy",         // Global
		"cilium_snat",          // All SNAT maps
		"cilium_tunnel",        // Global
		"from-container",       // Prog name
		"to-container",         // Prog name
	}
)

// Init initializes the datapath cache with base program hashes derived from
// the LocalNodeConfiguration.
func Init(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration) {
	once.Do(func() {
		templateCache = NewObjectCache(dp, nodeCfg)
		ignorePrefixes := ignoredELFPrefixes
		if !option.Config.EnableIPv4 {
			ignorePrefixes = append(ignorePrefixes, "LXC_IPV4")
		}
		if !option.Config.EnableIPv6 {
			ignorePrefixes = append(ignorePrefixes, "LXC_IP_")
		}
		elf.IgnoreSymbolPrefixes(ignorePrefixes)
	})
	templateCache.Update(nodeCfg)
}

// RestoreTemplates populates the object cache from templates on the filesystem
// at the specified path.
func RestoreTemplates(stateDir string) error {
	// Simplest implementation: Just garbage-collect everything.
	// In future we should make this smarter.
	path := filepath.Join(stateDir, defaults.TemplatesDir)
	err := os.RemoveAll(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return &os.PathError{
		Op:   "failed to remove old BPF templates",
		Path: path,
		Err:  err,
	}
}

// objectCache is a map from a hash of the datapath to the path on the
// filesystem where its corresponding BPF object file exists.
type objectCache struct {
	lock.Mutex
	datapath.Datapath

	workingDirectory string
	baseHash         *datapathHash

	// newTemplates is notified whenever template is added to the objectCache.
	newTemplates        chan string
	templateWatcherDone chan struct{}

	// toPath maps a hash to the filesystem path of the corresponding object.
	toPath map[string]string

	// compileQueue maps a hash to a queue which ensures that only one
	// attempt is made concurrently to compile the corresponding template.
	compileQueue map[string]*serializer.FunctionQueue
}

func newObjectCache(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration, workingDir string) *objectCache {
	oc := &objectCache{
		Datapath:            dp,
		workingDirectory:    workingDir,
		newTemplates:        make(chan string, templateWatcherQueueSize),
		templateWatcherDone: make(chan struct{}),
		toPath:              make(map[string]string),
		compileQueue:        make(map[string]*serializer.FunctionQueue),
	}
	oc.Update(nodeCfg)
	controller.NewManager().UpdateController("template-dir-watcher",
		controller.ControllerParams{
			DoFunc: oc.watchTemplatesDirectory,
			// No run interval but needs to re-run on errors.
		})

	return oc
}

// NewObjectCache creates a new cache for datapath objects, basing the hash
// upon the configuration of the datapath and the specified node configuration.
func NewObjectCache(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration) *objectCache {
	return newObjectCache(dp, nodeCfg, option.Config.StateDir)
}

// Update may be called to update the base hash for configuration of datapath
// configuration that applies across the node.
func (o *objectCache) Update(nodeCfg *datapath.LocalNodeConfiguration) {
	newHash := hashDatapath(o.Datapath, nodeCfg, nil, nil)

	o.Lock()
	defer o.Unlock()
	o.baseHash = newHash
}

// serialize finds the channel that serializes builds against the same hash.
// Returns the channel and whether or not the caller needs to compile the
// datapath for this hash.
func (o *objectCache) serialize(hash string) (fq *serializer.FunctionQueue, found bool) {
	o.Lock()
	defer o.Unlock()

	fq, compiled := o.compileQueue[hash]
	if !compiled {
		fq = serializer.NewFunctionQueue(1)
		o.compileQueue[hash] = fq
	}
	return fq, compiled
}

func (o *objectCache) lookup(hash string) (string, bool) {
	o.Lock()
	defer o.Unlock()
	path, exists := o.toPath[hash]
	return path, exists
}

func (o *objectCache) insert(hash, objectPath string) error {
	o.Lock()
	defer o.Unlock()
	o.toPath[hash] = objectPath

	scopedLog := log.WithField(logfields.Path, objectPath)
	select {
	case o.newTemplates <- objectPath:
	case <-o.templateWatcherDone:
		// This means that the controller was stopped and Cilium is
		// shutting down; don't bother complaining too loudly.
		scopedLog.Debug("Failed to watch for template filesystem changes")
	default:
		// Unusual case; send on channel was blocked.
		scopedLog.Warn("Failed to watch for template filesystem changes")
	}
	return nil
}

func (o *objectCache) delete(hash string) {
	o.Lock()
	defer o.Unlock()
	delete(o.toPath, hash)
	delete(o.compileQueue, hash)
}

// build attempts to compile and cache a datapath template object file
// corresponding to the specified endpoint configuration.
func (o *objectCache) build(ctx context.Context, cfg *templateCfg, hash string) error {
	templatePath := filepath.Join(o.workingDirectory, defaults.TemplatesDir, hash)
	headerPath := filepath.Join(templatePath, common.CHeaderFileName)
	objectPath := filepath.Join(templatePath, endpointObj)

	if err := os.MkdirAll(templatePath, defaults.StateDirRights); err != nil {
		return &os.PathError{
			Op:   "failed to create template directory",
			Path: templatePath,
			Err:  err,
		}
	}

	f, err := os.Create(headerPath)
	if err != nil {
		return &os.PathError{
			Op:   "failed to open template header for writing",
			Path: headerPath,
			Err:  err,
		}
	}

	if err = o.Datapath.WriteEndpointConfig(f, cfg); err != nil {
		return &os.PathError{
			Op:   "failed to write template header",
			Path: headerPath,
			Err:  err,
		}
	}

	cfg.stats.bpfCompilation.Start()
	err = compileTemplate(ctx, templatePath)
	cfg.stats.bpfCompilation.End(err == nil)
	if err != nil {
		return &os.PathError{
			Op:   "failed to compile template program",
			Path: templatePath,
			Err:  err,
		}
	}

	log.WithFields(logrus.Fields{
		logfields.Path:               objectPath,
		logfields.BPFCompilationTime: cfg.stats.bpfCompilation.Total(),
	}).Info("Compiled new BPF template")

	o.insert(hash, objectPath)
	return nil
}

// fetchOrCompile attempts to fetch the path to the datapath object
// corresponding to the provided endpoint configuration, or if this
// configuration is not yet compiled, compiles it. It will block if multiple
// threads attempt to concurrently fetchOrCompile a template binary for the
// same set of EndpointConfiguration.
//
// Returns the path to the compiled template datapath object and whether the
// object was compiled, or an error.
func (o *objectCache) fetchOrCompile(ctx context.Context, cfg datapath.EndpointConfiguration, stats *SpanStat) (path string, compiled bool, err error) {
	var hash string
	hash, err = o.baseHash.sumEndpoint(o, cfg, false)
	if err != nil {
		return "", false, err
	}

	// Capture the time spent waiting for the template to compile.
	if stats != nil {
		stats.bpfWaitForELF.Start()
		defer func() {
			// Wrap to ensure that "err" is compared upon return.
			stats.bpfWaitForELF.End(err == nil)
		}()
	}

	scopedLog := log.WithField(logfields.BPFHeaderfileHash, hash)

	// Serializes attempts to compile this cfg.
	fq, compiled := o.serialize(hash)
	if !compiled {
		fq.Enqueue(func() error {
			defer fq.Stop()
			templateCfg := wrap(cfg, stats)
			err := o.build(ctx, templateCfg, hash)
			if err != nil {
				scopedLog.WithError(err).Error("BPF template object creation failed")
			}
			return err
		}, serializer.NoRetry)
	}

	// Wait until the build completes.
	if err = fq.Wait(ctx); err != nil {
		scopedLog.WithError(err).Warning("Error while waiting for BPF template compilation")
		return "", false, fmt.Errorf("BPF template compilation failed: %s", err)
	}

	// Fetch the result of the compilation.
	path, ok := o.lookup(hash)
	if !ok {
		err := fmt.Errorf("Could not locate previously compiled BPF template")
		scopedLog.WithError(err).Warning("BPF template compilation unsuccessful")
		return "", false, err
	}

	return path, !compiled, nil
}

func (o *objectCache) watchTemplatesDirectory(ctx context.Context) error {
	templateWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() {
		close(o.templateWatcherDone)
		templateWatcher.Close()
	}()

	for {
		select {
		// Watch for new templates being compiled and add to the filesystem watcher
		case templatePath := <-o.newTemplates:
			if err = templateWatcher.Add(templatePath); err != nil {
				log.WithFields(logrus.Fields{
					logfields.Path: templatePath,
				}).WithError(err).Warning("Failed to watch templates directory")
			} else {
				log.WithFields(logrus.Fields{
					logfields.Path: templatePath,
				}).Debug("Watching template path")
			}
		// Handle filesystem deletes for current templates
		case event, open := <-templateWatcher.Events:
			if !open {
				break
			}
			if event.Op&fsnotify.Remove != 0 {
				log.WithField(logfields.Path, event.Name).Debug("Detected template removal")
				templateHash := filepath.Base(filepath.Dir(event.Name))
				o.delete(templateHash)
			} else {
				log.WithField("event", event).Debug("Ignoring template FS event")
			}
		case err, _ = <-templateWatcher.Errors:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// EndpointHash hashes the specified endpoint configuration with the current
// datapath hash cache and returns the hash as string.
func EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	return templateCache.baseHash.sumEndpoint(templateCache, cfg, true)
}
