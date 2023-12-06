// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var ignoredELFPrefixes = []string{
	"2/",                          // Calls within the endpoint
	"HOST_IP",                     // Global
	"IPV6_NODEPORT",               // Global
	"ROUTER_IP",                   // Global
	"SNAT_IPV6_EXTERNAL",          // Global
	"cilium_auth_map",             // Global
	"cilium_call_policy",          // Global
	"cilium_egresscall_policy",    // Global
	"cilium_capture",              // Global
	"cilium_ct",                   // All CT maps, including local
	"cilium_encrypt_state",        // Global
	"cilium_events",               // Global
	"cilium_ipcache",              // Global
	"cilium_ktime",                // Global
	"cilium_lb",                   // Global
	"cilium_lxc",                  // Global
	"cilium_metrics",              // Global
	"cilium_nodeport_neigh",       // All nodeport neigh maps
	"cilium_node_map",             // Global
	"cilium_policy",               // All policy maps
	"cilium_proxy",                // Global
	"cilium_runtime_config",       // Global
	"cilium_signals",              // Global
	"cilium_snat",                 // All SNAT maps
	"cilium_tail_call_buffer",     // Global
	"cilium_tunnel",               // Global
	"cilium_ipv4_frag_datagrams",  // Global
	"cilium_ipmasq",               // Global
	"cilium_throttle",             // Global
	"cilium_egress_gw_policy_v4",  // Global
	"cilium_srv6_policy_v4",       // Global
	"cilium_srv6_policy_v6",       // Global
	"cilium_srv6_vrf_v4",          // Global
	"cilium_srv6_vrf_v6",          // Global
	"cilium_srv6_state_v4",        // Global
	"cilium_srv6_state_v6",        // Global
	"cilium_srv6_sid",             // Global
	"cilium_vtep_map",             // Global
	"cilium_per_cluster_ct",       // Global
	"cilium_per_cluster_snat",     // Global
	"cilium_world_cidrs4",         // Global
	"cilium_l2_responder_v4",      // Global
	"cilium_ratelimit",            // Global
	"cilium_ratelimit_metrics",    // Global
	"cilium_mcast_group_v4_outer", // Global
	"tc",                          // Program Section
	"xdp",                         // Program Section
	".BTF",                        // Debug
	".BTF.ext",                    // Debug
	".debug_ranges",               // Debug
	".debug_info",                 // Debug
	".debug_line",                 // Debug
	".debug_frame",                // Debug
	".debug_loc",                  // Debug
	// Endpoint IPv6 address. It's possible for the template object to have
	// these symbols while the endpoint doesn't, if IPv6 was just enabled and
	// the endpoint restored.
	"LXC_IP_",
	// The default val (14) is used for all devices except for L2-less devices
	// for which we set ETH_HLEN=0 during load time.
	"ETH_HLEN",
	// identity_length is global configuration value that is used to set the bit-length of identity
	// in a numeric identity.
	"identity_length",
}

// RestoreTemplates populates the object cache from templates on the filesystem
// at the specified path.
func (l *loader) RestoreTemplates(stateDir string) error {
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

	// objects maps a hash to a queue which ensures that only one
	// attempt is made concurrently to compile the corresponding template.
	objects map[string]*cachedObject
}

type cachedObject struct {
	// Protects state in cachedObject. Also used to serialize compilation attempts.
	lock.Mutex

	// The path at which the object is cached. May be empty if there hasn't
	// been a successful compile yet.
	path string
}

func newObjectCache(c datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration, workingDir string) *objectCache {
	oc := &objectCache{
		ConfigWriter:     c,
		workingDirectory: workingDir,
		objects:          make(map[string]*cachedObject),
	}
	oc.Update(nodeCfg)
	return oc
}

// Update may be called to update the base hash for configuration of datapath
// configuration that applies across the node.
func (o *objectCache) Update(nodeCfg *datapath.LocalNodeConfiguration) {
	newHash := hashDatapath(o.ConfigWriter, nodeCfg, nil, nil)

	o.Lock()
	defer o.Unlock()
	o.baseHash = newHash
}

// serialize access to an abitrary key.
//
// Lock the returned object to ensure mutual exclusion.
func (o *objectCache) serialize(key string) *cachedObject {
	o.Lock()
	defer o.Unlock()

	obj, ok := o.objects[key]
	if !ok {
		obj = new(cachedObject)
		o.objects[key] = obj
	}
	return obj
}

// build attempts to compile and cache a datapath template object file
// corresponding to the specified endpoint configuration.
func (o *objectCache) build(ctx context.Context, cfg *templateCfg, hash string) (string, error) {
	isHost := cfg.IsHost()
	templatePath := filepath.Join(o.workingDirectory, defaults.TemplatesDir, hash)
	dir := &directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		Output:  templatePath,
		State:   templatePath,
	}
	prog := epProg
	if isHost {
		prog = hostEpProg
	}

	objectPath := prog.AbsoluteOutput(dir)

	if err := os.MkdirAll(dir.Output, defaults.StateDirRights); err != nil {
		return "", fmt.Errorf("failed to create template directory: %w", err)
	}

	headerPath := filepath.Join(dir.State, common.CHeaderFileName)
	f, err := os.Create(headerPath)
	if err != nil {
		return "", fmt.Errorf("failed to open template header for writing: %w", err)
	}
	defer f.Close()
	if err = o.ConfigWriter.WriteEndpointConfig(f, cfg); err != nil {
		return "", fmt.Errorf("failed to write template header: %w", err)
	}

	cfg.stats.BpfCompilation.Start()
	err = compileDatapath(ctx, dir, isHost, log)
	cfg.stats.BpfCompilation.End(err == nil)
	if err != nil {
		return "", fmt.Errorf("failed to compile template program: %w", err)
	}

	log.WithFields(logrus.Fields{
		logfields.Path:               objectPath,
		logfields.BPFCompilationTime: cfg.stats.BpfCompilation.Total(),
	}).Info("Compiled new BPF template")

	return objectPath, nil
}

// fetchOrCompile attempts to fetch the path to the datapath object
// corresponding to the provided endpoint configuration, or if this
// configuration is not yet compiled, compiles it. It will block if multiple
// threads attempt to concurrently fetchOrCompile a template binary for the
// same set of EndpointConfiguration.
//
// Returns the path to the compiled template datapath object and whether the
// object was compiled, or an error.
func (o *objectCache) fetchOrCompile(ctx context.Context, cfg datapath.EndpointConfiguration, stats *metrics.SpanStat) (file *os.File, compiled bool, err error) {
	var hash string
	hash, err = o.baseHash.sumEndpoint(o, cfg, false)
	if err != nil {
		return nil, false, err
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

	obj := o.serialize(hash)

	// Only allow a single concurrent compilation.
	obj.Lock()
	defer obj.Unlock()

	if obj.path != "" {
		// Only attempt to use a cached object if we previously built this object.
		// Otherwise we risk reusing a previous process' output since we're not
		// guaranteed an empty working directory.
		if cached, err := os.Open(obj.path); err == nil {
			return cached, false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, false, err
		}
	}

	path, err := o.build(ctx, wrap(cfg, stats), hash)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			scopedLog.WithError(err).Error("BPF template object creation failed")
		}
		return nil, false, err
	}

	output, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}

	obj.path = path
	return output, !compiled, nil
}
