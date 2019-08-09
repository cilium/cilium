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
	"net"
	"os"
	"path"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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

// Loader is a wrapper structure around operations related to compiling,
// loading, and reloading datapath programs.
type Loader struct {
	once sync.Once

	// templateCache is the cache of pre-compiled datapaths.
	templateCache *objectCache
}

// Init initializes the datapath cache with base program hashes derived from
// the LocalNodeConfiguration.
func (l *Loader) Init(dp datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration) {
	l.once.Do(func() {
		l.templateCache = NewObjectCache(dp, nodeCfg)
		ignorePrefixes := ignoredELFPrefixes
		if !option.Config.EnableIPv4 {
			ignorePrefixes = append(ignorePrefixes, "LXC_IPV4")
		}
		if !option.Config.EnableIPv6 {
			ignorePrefixes = append(ignorePrefixes, "LXC_IP_")
		}
		elf.IgnoreSymbolPrefixes(ignorePrefixes)
	})
	l.templateCache.Update(nodeCfg)
}

func upsertEndpointRoute(ep datapath.Endpoint, ip net.IPNet) error {
	endpointRoute := route.Route{
		Prefix: ip,
		Device: ep.InterfaceName(),
		Scope:  netlink.SCOPE_LINK,
	}

	_, err := route.Upsert(endpointRoute, nil)
	return err
}

func removeEndpointRoute(ep datapath.Endpoint, ip net.IPNet) error {
	return route.Delete(route.Route{
		Prefix: ip,
		Device: ep.InterfaceName(),
		Scope:  netlink.SCOPE_LINK,
	})
}

func (l *Loader) reloadDatapath(ctx context.Context, ep datapath.Endpoint, dirs *directoryInfo) error {
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
		if err := l.replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint, dirIngress); err != nil {
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
			if err := l.replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolToEndpoint, dirEgress); err != nil {
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

	if ep.RequireEndpointRoute() {
		if ip := ep.IPv4Address(); ip.IsSet() {
			upsertEndpointRoute(ep, *ip.IPNet(32))
		}

		if ip := ep.IPv6Address(); ip.IsSet() {
			upsertEndpointRoute(ep, *ip.IPNet(128))
		}
	}

	return nil
}

func (l *Loader) compileAndLoad(ctx context.Context, ep datapath.Endpoint, dirs *directoryInfo, stats *metrics.SpanStat) error {
	debug := option.Config.BPFCompilationDebug
	stats.BpfCompilation.Start()
	err := compileDatapath(ctx, dirs, debug, ep.Logger(Subsystem))
	stats.BpfCompilation.End(err == nil)
	if err != nil {
		return err
	}

	stats.BpfLoadProg.Start()
	err = l.reloadDatapath(ctx, ep, dirs)
	stats.BpfLoadProg.End(err == nil)
	return err
}

// CompileAndLoad compiles the BPF datapath programs for the specified endpoint
// and loads it onto the interface associated with the endpoint.
//
// Expects the caller to have created the directory at the path ep.StateDir().
func (l *Loader) CompileAndLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	if ep == nil {
		log.Fatalf("LoadBPF() doesn't support non-endpoint load")
	}

	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
	return l.compileAndLoad(ctx, ep, &dirs, stats)
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
func (l *Loader) CompileOrLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	templatePath, _, err := l.templateCache.fetchOrCompile(ctx, ep, stats)
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

	stats.BpfWriteELF.Start()
	dstPath := path.Join(ep.StateDir(), endpointObj)
	opts, strings := ELFSubstitutions(ep)
	if err = template.Write(dstPath, opts, strings); err != nil {
		stats.BpfWriteELF.End(err == nil)
		return err
	}
	stats.BpfWriteELF.End(err == nil)

	return l.ReloadDatapath(ctx, ep, stats)
}

// ReloadDatapath reloads the BPF datapath pgorams for the specified endpoint.
func (l *Loader) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) (err error) {
	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
	stats.BpfLoadProg.Start()
	err = l.reloadDatapath(ctx, ep, &dirs)
	stats.BpfLoadProg.End(err == nil)
	return err
}

// Unload removes the datapath specific program aspects
func (l *Loader) Unload(ep datapath.Endpoint) {
	if ep.RequireEndpointRoute() {
		if ip := ep.IPv4Address(); ip.IsSet() {
			removeEndpointRoute(ep, *ip.IPNet(32))
		}

		if ip := ep.IPv6Address(); ip.IsSet() {
			removeEndpointRoute(ep, *ip.IPNet(128))
		}
	}
}

// EndpointHash hashes the specified endpoint configuration with the current
// datapath hash cache and returns the hash as string.
func (l *Loader) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	return l.templateCache.baseHash.sumEndpoint(l.templateCache, cfg, true)
}

// CallsMapPath gets the BPF Calls Map for the endpoint with the specified ID.
func (l *Loader) CallsMapPath(id uint16) string {
	return bpf.LocalMapPath(CallsMapName, id)
}
