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
	"path"

	"github.com/cilium/cilium/pkg/datapath"
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

// compileDatapath invokes the compiler and linker to create all state files for
// the BPF datapath, with the primary target being the BPF ELF binary.
//
// If debug is enabled, create also the following output files:
// * Preprocessed C
// * Assembly
// * Object compiled with debug symbols
func compileDatapath(ctx context.Context, ep endpoint, dirs *directoryInfo, debug bool) error {
	// TODO: Consider logging kernel/clang versions here too
	epLog := ep.Logger(Subsystem)

	// Write out assembly and preprocessing files for debugging purposes
	if debug {
		for _, p := range debugProgs {
			if err := compile(ctx, p, dirs, debug); err != nil {
				scopedLog := epLog.WithFields(logrus.Fields{
					logfields.Params: logfields.Repr(p),
					logfields.Debug:  debug,
				})
				scopedLog.WithError(err).Debug("JoinEP: Failed to compile")
				return err
			}
		}
	}

	// Compile the new program
	if err := compile(ctx, datapathProg, dirs, debug); err != nil {
		scopedLog := epLog.WithFields(logrus.Fields{
			logfields.Params: logfields.Repr(datapathProg),
			logfields.Debug:  false,
		})
		scopedLog.WithError(err).Warn("JoinEP: Failed to compile")
		return err
	}

	return nil
}

func reloadDatapath(ctx context.Context, ep endpoint, dirs *directoryInfo) error {
	// Replace the current program
	objPath := path.Join(dirs.Output, endpointObj)
	if ep.HasIpvlanDataPath() {
		if err := graftDatapath(ctx, ep.MapPath(), objPath, symbolFromEndpoint); err != nil {
			scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
				logfields.Path: objPath,
			})
			scopedLog.WithError(err).Warn("JoinEP: Failed to load program")
			return err
		}
	} else {
		if err := replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint); err != nil {
			scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
				logfields.Path: objPath,
				logfields.Veth: ep.InterfaceName(),
			})
			scopedLog.WithError(err).Warn("JoinEP: Failed to load program")
			return err
		}
	}

	return nil
}

func compileAndLoad(ctx context.Context, ep endpoint, dirs *directoryInfo) error {
	debug := option.Config.BPFCompilationDebug
	if err := compileDatapath(ctx, ep, dirs, debug); err != nil {
		return err
	}

	return reloadDatapath(ctx, ep, dirs)
}

// CompileAndLoad compiles the BPF datapath programs for the specified endpoint
// and loads it onto the interface associated with the endpoint.
//
// Expects the caller to have created the directory at the path ep.StateDir().
func CompileAndLoad(ctx context.Context, ep endpoint) error {
	if ep == nil {
		log.Fatalf("LoadBPF() doesn't support non-endpoint load")
	}

	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
	return compileAndLoad(ctx, ep, &dirs)
}

func CompileOrLoad(ctx context.Context, ep endpoint, stats *SpanStat) error {
	templatePath, _, err := elfCache.FetchOrCompile(ctx, ep, stats)
	if err != nil {
		return err
	}

	template, err := elf.Open(templatePath)
	if err != nil {
		return err
	}
	defer template.Close()

	dstPath := path.Join(ep.StateDir(), "bpf_lxc.o")
	opts, strings := ELFSubstitutions(ep)
	if err = template.Write(dstPath, opts, strings); err != nil {
		return err
	}

	return ReloadDatapath(ctx, ep)
}

func ReloadDatapath(ctx context.Context, ep endpoint) error {
	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
	return reloadDatapath(ctx, ep, &dirs)
}

func compileWithPath(ctx context.Context, src, outDir, outBase string) error {
	debug := option.Config.BPFCompilationDebug
	prog := progInfo{
		Source:     src,
		Output:     outBase,
		OutputType: outputObject,
	}
	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		Output:  outDir,
		State:   option.Config.StateDir,
	}
	return compile(ctx, &prog, &dirs, debug)
}

// CompileEndpoint compiles a BPF program generating a template object file.
func CompileEndpoint(ctx context.Context, out string) error {
	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		Output:  out,
		State:   out,
	}
	return compile(ctx, datapathProg, &dirs, option.Config.BPFCompilationDebug)
}

// Compile compiles a BPF program generating an object file.
func Compile(ctx context.Context, src string, out string) error {
	return compileWithPath(ctx, src, option.Config.StateDir, out)
}

// CompileToFullPath compiles a BPF program generating an object file, placing
// it at the fully specified path 'out'.
func CompileToFullPath(ctx context.Context, src, out string) error {
	dir := path.Dir(out)
	base := path.Base(out)
	return compileWithPath(ctx, src, dir, base)
}
