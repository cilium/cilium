// Copyright 2018-2019 Authors of Cilium
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
	"path"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

var (
	Subsystem = "datapath-loader"
	log       = logging.DefaultLogger.WithField(logfields.LogSubsys, Subsystem)
)

const (
	symbolFromEndpoint = "from-container"
	symbolToEndpoint   = "to-container"

	dirIngress = "ingress"
	dirEgress  = "egress"
)

// endpoint provides access to endpoint information that is necessary to
// compile and load the datapath.
type endpoint interface {
	datapath.EndpointConfiguration
	InterfaceName() string
	Logger(subsystem string) *logrus.Entry
	StateDir() string
	MapPath() string
}

func reloadDatapath(ctx context.Context, ep endpoint, dirs *directoryInfo) error {
	// Replace the current program
	objPath := path.Join(dirs.Output, endpointObj)
	if ep.HasIpvlanDataPath() {
		if err := graftDatapath(ctx, ep.MapPath(), objPath, symbolFromEndpoint); err != nil {
			scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
				logfields.Path: objPath,
			})
			// Don't log an error here if the context was canceled or timed out;
			// this log message should only represent failures with respect to
			// loading the program.
			if ctx.Err() == nil {
				scopedLog.WithError(err).Warn("JoinEP: Failed to load program")
			}
			return err
		}
	} else {
		if err := replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint, dirIngress); err != nil {
			scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
				logfields.Path: objPath,
				logfields.Veth: ep.InterfaceName(),
			})
			// Don't log an error here if the context was canceled or timed out;
			// this log message should only represent failures with respect to
			// loading the program.
			if ctx.Err() == nil {
				scopedLog.WithError(err).Warn("JoinEP: Failed to load program")
			}
			return err
		}

		if ep.RequireEgressProg() {
			if err := replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolToEndpoint, dirEgress); err != nil {
				scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
					logfields.Path: objPath,
					logfields.Veth: ep.InterfaceName(),
				})
				// Don't log an error here if the context was canceled or timed out;
				// this log message should only represent failures with respect to
				// loading the program.
				if ctx.Err() == nil {
					scopedLog.WithError(err).Warn("JoinEP: Failed to load program")
				}
				return err
			}
		}
	}

	return nil
}

func compileAndLoad(ctx context.Context, ep endpoint, dirs *directoryInfo, stats *SpanStat) error {
	debug := option.Config.BPFCompilationDebug
	stats.bpfCompilation.Start()
	err := compileDatapath(ctx, dirs, debug, ep.Logger(Subsystem))
	stats.bpfCompilation.End(err == nil)
	if err != nil {
		return err
	}

	stats.bpfLoadProg.Start()
	err = reloadDatapath(ctx, ep, dirs)
	stats.bpfLoadProg.End(err == nil)
	return err
}

// CompileAndLoad compiles the BPF datapath programs for the specified endpoint
// and loads it onto the interface associated with the endpoint.
//
// Expects the caller to have created the directory at the path ep.StateDir().
func CompileAndLoad(ctx context.Context, ep endpoint, stats *SpanStat) error {
	if ep == nil {
		log.Fatalf("LoadBPF() doesn't support non-endpoint load")
	}

	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
	return compileAndLoad(ctx, ep, &dirs, stats)
}

// CompileOrLoad loads the BPF datapath programs for the specified endpoint.
//
// In contrast with CompileAndLoad(), it attempts to find a pre-compiled
// template datapath object to use, to avoid a costly compile operation.
// Only if there is no existing template that has the same configuration
// parameters as the specified endpoint, this function will compile a new
// template for this configuration.
//
// This function will block if the cache does not contain an entry for the
// same EndpointConfiguration and multiple goroutines attempt to concurrently
// CompileOrLoad with the same configuration parameters. When the first
// goroutine completes compilation of the template, all other CompileOrLoad
// invocations will be released.
func CompileOrLoad(ctx context.Context, ep endpoint, stats *SpanStat) error {
	templatePath, _, err := templateCache.fetchOrCompile(ctx, ep, stats)
	if err != nil {
		return err
	}

	template, err := elf.Open(templatePath)
	if err != nil {
		return err
	}
	defer template.Close()

	symPath := path.Join(ep.StateDir(), defaults.TemplatePath)
	if _, err := os.Stat(symPath); err == nil {
		if err = os.RemoveAll(symPath); err != nil {
			return &os.PathError{
				Op:   "Failed to remove old symlink",
				Path: symPath,
				Err:  err,
			}
		}
	} else if !os.IsNotExist(err) {
		return &os.PathError{
			Op:   "Failed to locate symlink",
			Path: symPath,
			Err:  err,
		}
	}
	if err := os.Symlink(templatePath, symPath); err != nil {
		return &os.PathError{
			Op:   fmt.Sprintf("Failed to create symlink to %s", templatePath),
			Path: symPath,
			Err:  err,
		}
	}

	stats.bpfWriteELF.Start()
	dstPath := path.Join(ep.StateDir(), endpointObj)
	opts, strings := ELFSubstitutions(ep)
	if err = template.Write(dstPath, opts, strings); err != nil {
		stats.bpfWriteELF.End(err == nil)
		return err
	}
	stats.bpfWriteELF.End(err == nil)

	return ReloadDatapath(ctx, ep, stats)
}

func ReloadDatapath(ctx context.Context, ep endpoint, stats *SpanStat) (err error) {
	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
	stats.bpfLoadProg.Start()
	err = reloadDatapath(ctx, ep, &dirs)
	stats.bpfLoadProg.End(err == nil)
	return err
}
