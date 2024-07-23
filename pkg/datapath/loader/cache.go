// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// objectCache amortises the cost of BPF compilation for endpoints.
type objectCache struct {
	lock.Mutex
	datapath.ConfigWriter

	// The directory used for caching. Must not be accessed by another process.
	workingDirectory string

	baseHash datapathHash

	// The cached objects.
	objects map[string]*cachedSpec
}

type cachedSpec struct {
	// Protects state, also used to serialize compilation attempts.
	lock.Mutex

	// The compiled and parsed spec. May be nil if no compilation has happened yet.
	spec *ebpf.CollectionSpec
}

func newObjectCache(c datapath.ConfigWriter, workingDir string) *objectCache {
	return &objectCache{
		ConfigWriter:     c,
		workingDirectory: workingDir,
		objects:          make(map[string]*cachedSpec),
	}
}

// UpdateDatapathHash invalidates the object cache if the configuration of the
// datapath has changed.
func (o *objectCache) UpdateDatapathHash(nodeCfg *datapath.LocalNodeConfiguration) error {
	newHash, err := hashDatapath(o.ConfigWriter, nodeCfg)
	if err != nil {
		return fmt.Errorf("hash datapath config: %w", err)
	}

	// Prevent new compilation from starting.
	o.Lock()
	defer o.Unlock()

	// Don't invalidate if the hash is the same.
	if bytes.Equal(newHash, o.baseHash) {
		return nil
	}

	// Wait until all concurrent compilation has finished.
	for _, obj := range o.objects {
		obj.Lock()
	}

	if err := os.RemoveAll(o.workingDirectory); err != nil {
		for _, obj := range o.objects {
			obj.Unlock()
		}

		return err
	}

	o.baseHash = newHash
	o.objects = make(map[string]*cachedSpec)
	return nil
}

// serialize access to an abitrary key.
//
// The caller must call Unlock on the returned object.
func (o *objectCache) serialize(key string) *cachedSpec {
	o.Lock()
	defer o.Unlock()

	obj, ok := o.objects[key]
	if !ok {
		obj = new(cachedSpec)
		o.objects[key] = obj
	}

	obj.Lock()
	return obj
}

// build attempts to compile and cache a datapath template object file
// corresponding to the specified endpoint configuration.
func (o *objectCache) build(ctx context.Context, nodeCfg *datapath.LocalNodeConfiguration, cfg datapath.EndpointConfiguration, stats *metrics.SpanStat, dir *directoryInfo, hash string) (string, error) {
	isHost := cfg.IsHost()
	templatePath := filepath.Join(o.workingDirectory, hash)
	dir = &directoryInfo{
		Library: dir.Library,
		Runtime: dir.Runtime,
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
	if err = o.ConfigWriter.WriteEndpointConfig(f, nodeCfg, cfg); err != nil {
		return "", fmt.Errorf("failed to write template header: %w", err)
	}

	stats.BpfCompilation.Start()
	err = compileDatapath(ctx, dir, isHost, log)
	stats.BpfCompilation.End(err == nil)
	if err != nil {
		return "", fmt.Errorf("failed to compile template program: %w", err)
	}

	log.WithFields(logrus.Fields{
		logfields.Path:               objectPath,
		logfields.BPFCompilationTime: stats.BpfCompilation.Total(),
	}).Info("Compiled new BPF template")

	return objectPath, nil
}

// fetchOrCompile attempts to fetch the path to the datapath object
// corresponding to the provided endpoint configuration, or if this
// configuration is not yet compiled, compiles it. It will block if multiple
// threads attempt to concurrently fetchOrCompile a template binary for the
// same set of EndpointConfiguration.
//
// Returns a copy of the compiled and parsed ELF and a hash identifying a cached entry.
func (o *objectCache) fetchOrCompile(ctx context.Context, nodeCfg *datapath.LocalNodeConfiguration, cfg datapath.EndpointConfiguration, dir *directoryInfo, stats *metrics.SpanStat) (spec *ebpf.CollectionSpec, hash string, err error) {
	cfg = wrap(cfg)

	hash, err = o.baseHash.hashTemplate(o, nodeCfg, cfg)
	if err != nil {
		return nil, "", err
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

	// Only allow a single concurrent compilation per hash.
	obj := o.serialize(hash)
	defer obj.Unlock()

	if obj.spec != nil {
		return obj.spec.Copy(), hash, nil
	}

	if stats == nil {
		stats = &metrics.SpanStat{}
	}

	path, err := o.build(ctx, nodeCfg, cfg, stats, dir, hash)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			scopedLog.WithError(err).Error("BPF template object creation failed")
		}
		return nil, "", err
	}

	obj.spec, err = bpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, "", fmt.Errorf("load eBPF ELF %s: %w", path, err)
	}

	return obj.spec.Copy(), hash, nil
}
