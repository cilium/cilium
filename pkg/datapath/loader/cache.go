// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf/analyze"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// objectCache amortises the cost of BPF compilation for endpoints.
type objectCache struct {
	logger *slog.Logger

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

	// The path to the compiled object file, if it exists.
	path string
}

func newObjectCache(logger *slog.Logger, c datapath.ConfigWriter, workingDir string) *objectCache {
	return &objectCache{
		logger:           logger,
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
	// Unlock all objects so that race detector doesn't complain about potential
	// deadlocks.
	for _, obj := range o.objects {
		obj.Unlock()
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
	err = compileDatapath(ctx, o.logger, dir, isHost)
	stats.BpfCompilation.End(err == nil)
	if err != nil {
		return "", fmt.Errorf("failed to compile template program: %w", err)
	}

	o.logger.Info(
		"Compiled new BPF template",
		logfields.Path, objectPath,
		logfields.BPFCompilationTime, stats.BpfCompilation.Total(),
	)

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

	// Only allow a single concurrent compilation per hash.
	obj := o.serialize(hash)
	defer obj.Unlock()

	// The serialize call might have blocked for a significant amount of time
	// if another compilation was in progress. Make sure that the endpoint is
	// still alive, to bail out early otherwise, and prevent doing unnecessary
	// operations that would likely fail.
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	default:
	}

	if obj.spec != nil {
		o.logger.Debug("Using cached BPF template", logfields.Object, obj.path)
		return obj.spec.Copy(), hash, nil
	}

	if stats == nil {
		stats = &metrics.SpanStat{}
	}

	path, err := o.build(ctx, nodeCfg, cfg, stats, dir, hash)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			o.logger.Error(
				"BPF template object creation failed",
				logfields.Error, err,
				logfields.BPFHeaderfileHash, hash,
			)
		}
		return nil, "", err
	}

	obj.path = path

	obj.spec, err = ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, "", fmt.Errorf("load eBPF ELF %s: %w", path, err)
	}

	// Precompute the Blocks for each ProgramSpec in the CollectionSpec so
	// downstream callers don't need to compute them again. This is expensive to
	// run, so do it only once per compilation. Control flow isn't expected to
	// be changed after compilation.
	for name, prog := range obj.spec.Programs {
		if _, err := analyze.MakeBlocks(prog.Instructions); err != nil {
			return nil, "", fmt.Errorf("making Blocks for ProgramSpec %s: %w", name, err)
		}
		o.logger.Debug("Precomputed Blocks", logfields.Object, name)
	}

	return obj.spec.Copy(), hash, nil
}
