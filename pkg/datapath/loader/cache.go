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
)

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
func (o *objectCache) build(ctx context.Context, nodeCfg *datapath.LocalNodeConfiguration, cfg datapath.EndpointConfiguration, stats *metrics.SpanStat, dir *directoryInfo, hash string) (string, error) {
	isHost := cfg.IsHost()
	templatePath := filepath.Join(o.workingDirectory, defaults.TemplatesDir, hash)
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
// Returns the path to the compiled template datapath object and whether the
// object was compiled, or an error.
func (o *objectCache) fetchOrCompile(ctx context.Context, nodeCfg *datapath.LocalNodeConfiguration, cfg datapath.EndpointConfiguration, dir *directoryInfo, stats *metrics.SpanStat) (file *os.File, compiled bool, err error) {
	cfg = wrap(cfg)

	var hash string
	hash, err = o.baseHash.sumEndpoint(o, nodeCfg, cfg, false)
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

	if stats == nil {
		stats = &metrics.SpanStat{}
	}

	path, err := o.build(ctx, nodeCfg, cfg, stats, dir, hash)
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
