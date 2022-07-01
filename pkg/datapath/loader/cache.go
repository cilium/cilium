// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/serializer"
)

const templateWatcherQueueSize = 10

var ignoredELFPrefixes = []string{
	"2/",                         // Calls within the endpoint
	"HOST_IP",                    // Global
	"IPV6_NODEPORT",              // Global
	"ROUTER_IP",                  // Global
	"SNAT_IPV6_EXTERNAL",         // Global
	"cilium_call_policy",         // Global
	"cilium_egresscall_policy",   // Global
	"cilium_capture",             // Global
	"cilium_ct",                  // All CT maps, including local
	"cilium_encrypt_state",       // Global
	"cilium_events",              // Global
	"cilium_ipcache",             // Global
	"cilium_ktime",               // Global
	"cilium_lb",                  // Global
	"cilium_lxc",                 // Global
	"cilium_metrics",             // Global
	"cilium_nodeport_neigh",      // All nodeport neigh maps
	"cilium_policy",              // All policy maps
	"cilium_proxy",               // Global
	"cilium_signals",             // Global
	"cilium_snat",                // All SNAT maps
	"cilium_tail_call_buffer",    // Global
	"cilium_tunnel",              // Global
	"cilium_ipv4_frag_datagrams", // Global
	"cilium_ipmasq",              // Global
	"cilium_throttle",            // Global
	"cilium_egress_gw_policy_v4", // Global
	"from-container",             // Prog name
	"to-container",               // Prog name
	"from-netdev",                // Prog name
	"from-host",                  // Prog name
	"to-netdev",                  // Prog name
	"to-host",                    // Prog name
	".BTF",                       // Debug
	".BTF.ext",                   // Debug
	".debug_ranges",              // Debug
	".debug_info",                // Debug
	".debug_line",                // Debug
	".debug_frame",               // Debug
	".debug_loc",                 // Debug
	// Endpoint IPv6 address. It's possible for the template object to have
	// these symbols while the endpoint doesn't, if IPv6 was just enabled and
	// the endpoint restored.
	"LXC_IP_",
	// The default val (14) is used for all devices except for L2-less devices
	// for which we set ETH_HLEN=0 during load time.
	"ETH_HLEN",
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
	datapath.ConfigWriter

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

func newObjectCache(c datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration, workingDir string) *objectCache {
	oc := &objectCache{
		ConfigWriter:        c,
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
func NewObjectCache(c datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration) *objectCache {
	return newObjectCache(c, nodeCfg, option.Config.StateDir)
}

// Update may be called to update the base hash for configuration of datapath
// configuration that applies across the node.
func (o *objectCache) Update(nodeCfg *datapath.LocalNodeConfiguration) {
	newHash := hashDatapath(o.ConfigWriter, nodeCfg, nil, nil)

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
	isHost := cfg.IsHost()
	templatePath := filepath.Join(o.workingDirectory, defaults.TemplatesDir, hash)
	headerPath := filepath.Join(templatePath, common.CHeaderFileName)
	epObj := endpointObj
	if isHost {
		epObj = hostEndpointObj
	}
	objectPath := filepath.Join(templatePath, epObj)

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

	if err = o.ConfigWriter.WriteEndpointConfig(f, cfg); err != nil {
		return &os.PathError{
			Op:   "failed to write template header",
			Path: headerPath,
			Err:  err,
		}
	}

	cfg.stats.BpfCompilation.Start()
	err = compileTemplate(ctx, templatePath, isHost)
	cfg.stats.BpfCompilation.End(err == nil)
	if err != nil {
		return &os.PathError{
			Op:   "failed to compile template program",
			Path: templatePath,
			Err:  err,
		}
	}

	log.WithFields(logrus.Fields{
		logfields.Path:               objectPath,
		logfields.BPFCompilationTime: cfg.stats.BpfCompilation.Total(),
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
func (o *objectCache) fetchOrCompile(ctx context.Context, cfg datapath.EndpointConfiguration, stats *metrics.SpanStat) (path string, compiled bool, err error) {
	var hash string
	hash, err = o.baseHash.sumEndpoint(o, cfg, false)
	if err != nil {
		return "", false, err
	}

	// Capture the time spent waiting for the template to compile.
	if stats != nil {
		stats.BpfWaitForELF.Start()
		defer func() {
			// Wrap to ensure that "err" is compared upon return.
			stats.BpfWaitForELF.End(err == nil)
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
				o.Lock()
				delete(o.compileQueue, hash)
				o.Unlock()
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
			if event.Op&fsnotify.Remove == fsnotify.Remove {
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
