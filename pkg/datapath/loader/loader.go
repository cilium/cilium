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
	"reflect"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	Subsystem = "datapath-loader"

	symbolFromEndpoint = "from-container"
	symbolToEndpoint   = "to-container"

	symbolFromHostNetdevEp = "from-netdev"
	symbolToHostNetdevEp   = "to-netdev"
	symbolFromHostEp       = "from-host"
	symbolToHostEp         = "to-host"

	dirIngress = "ingress"
	dirEgress  = "egress"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, Subsystem)

// Loader is a wrapper structure around operations related to compiling,
// loading, and reloading datapath programs.
type Loader struct {
	once sync.Once

	// templateCache is the cache of pre-compiled datapaths.
	templateCache *objectCache

	canDisableDwarfRelocations bool
}

// NewLoader returns a new loader.
func NewLoader(canDisableDwarfRelocations bool) *Loader {
	return &Loader{
		canDisableDwarfRelocations: canDisableDwarfRelocations,
	}
}

// Init initializes the datapath cache with base program hashes derived from
// the LocalNodeConfiguration.
func (l *Loader) init(dp datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration) {
	l.once.Do(func() {
		l.templateCache = NewObjectCache(dp, nodeCfg)
		ignorePrefixes := ignoredELFPrefixes
		if !option.Config.EnableIPv4 {
			ignorePrefixes = append(ignorePrefixes, "LXC_IPV4")
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

	_, err := route.Upsert(endpointRoute)
	return err
}

func removeEndpointRoute(ep datapath.Endpoint, ip net.IPNet) error {
	return route.Delete(route.Route{
		Prefix: ip,
		Device: ep.InterfaceName(),
		Scope:  netlink.SCOPE_LINK,
	})
}

// We need this function when patching an object file for which symbols were
// already substituted. During the first symbol substitutions, string symbols
// were replaced such that:
//   template_string -> string_for_endpoint
// Since we only want to replace one int symbol, we can nullify string
// substitutions with:
//   string_for_endpoint -> string_for_endpoint
// We cannot simply pass an empty map as the agent would complain that some
// symbol had no corresponding values.
func nullifyStringSubstitutions(strings map[string]string) map[string]string {
	nullStrings := make(map[string]string)
	for _, v := range strings {
		nullStrings[v] = v
	}
	return nullStrings
}

// Since we attach the host endpoint datapath to two different interfaces, we
// need two different NODE_MAC values. patchHostNetdevDatapath creates a new
// object file for the native device, from the object file for the host device
// (cilium_host).
// Since the two object files should only differ by the values of their
// NODE_MAC symbols, we can avoid a full compilation.
func patchHostNetdevDatapath(ep datapath.Endpoint, objPath, dstPath, ifName string,
	nodePortIPv4Addrs, nodePortIPv6Addrs map[string]net.IP) error {
	hostObj, err := elf.Open(objPath)
	if err != nil {
		return err
	}
	defer hostObj.Close()

	opts, strings := ELFSubstitutions(ep)

	// The NODE_MAC value is specific to each attachment interface.
	mac, err := link.GetHardwareAddr(ifName)
	if err != nil {
		return err
	}
	opts["NODE_MAC_1"] = sliceToBe32(mac[0:4])
	opts["NODE_MAC_2"] = uint32(sliceToBe16(mac[4:6]))

	ifIndex, err := link.GetIfIndex(ifName)
	if err != nil {
		return err
	}

	if option.Config.EnableNodePort {
		// First device from the list is used for direct routing between nodes
		directRoutingIface := option.Config.Devices[0]
		directRoutingIfIndex, err := link.GetIfIndex(directRoutingIface)
		if err != nil {
			return err
		}
		opts["DIRECT_ROUTING_DEV_IFINDEX"] = directRoutingIfIndex
		opts["NATIVE_DEV_IFINDEX"] = ifIndex
		if option.Config.EnableIPv4 {
			ipv4 := nodePortIPv4Addrs[directRoutingIface]
			opts["IPV4_DIRECT_ROUTING"] = byteorder.HostSliceToNetwork(ipv4, reflect.Uint32).(uint32)
			ipv4 = nodePortIPv4Addrs[ifName]
			opts["IPV4_NODEPORT"] = byteorder.HostSliceToNetwork(ipv4, reflect.Uint32).(uint32)
		}
		if option.Config.EnableIPv6 {
			directRoutingIPv6 := nodePortIPv6Addrs[directRoutingIface]
			opts["IPV6_DIRECT_ROUTING_1"] = sliceToBe32(directRoutingIPv6[0:4])
			opts["IPV6_DIRECT_ROUTING_2"] = sliceToBe32(directRoutingIPv6[4:8])
			opts["IPV6_DIRECT_ROUTING_3"] = sliceToBe32(directRoutingIPv6[8:12])
			opts["IPV6_DIRECT_ROUTING_4"] = sliceToBe32(directRoutingIPv6[12:16])
			nodePortIPv6 := nodePortIPv6Addrs[ifName]
			opts["IPV6_NODEPORT_1"] = sliceToBe32(nodePortIPv6[0:4])
			opts["IPV6_NODEPORT_2"] = sliceToBe32(nodePortIPv6[4:8])
			opts["IPV6_NODEPORT_3"] = sliceToBe32(nodePortIPv6[8:12])
			opts["IPV6_NODEPORT_4"] = sliceToBe32(nodePortIPv6[12:16])
		}
	}

	// Among string substitutions, only the calls map name is specific to each
	// attachment interface.
	strings = nullifyStringSubstitutions(strings)
	callsMapHostDevice := bpf.LocalMapName(callsmap.HostMapName, uint16(ep.GetID()))
	strings[callsMapHostDevice] = bpf.LocalMapName(callsmap.NetdevMapName, uint16(ifIndex))

	return hostObj.Write(dstPath, opts, strings)
}

// reloadHostDatapath loads bpf_host programs attached to the host device
// (usually cilium_host) and the native devices if any. To that end, it
// uses a single object file, pointed to by objPath, compiled for the host
// device and patches it with values for native devices if needed.
// Symbols in objPath have already been substituted with the appropriate values
// for the host device. Thus, when packing the object file again for the native
// devices, we don't need to substitute most values (see
// nullifyStringSubstitutions above).
// reloadHostDatapath skips native devices that do not exist just before
// loading. If loading+attaching fails later on however, reloadHostDatapath
// will return with an error. Failing to load or to attach the host device
// always results in reloadHostDatapath returning with an error.
func (l *Loader) reloadHostDatapath(ctx context.Context, ep datapath.Endpoint, objPath string) error {
	nbInterfaces := len(option.Config.Devices) + 2
	symbols := make([]string, 2, nbInterfaces)
	directions := make([]string, 2, nbInterfaces)
	objPaths := make([]string, 2, nbInterfaces)
	interfaceNames := make([]string, 2, nbInterfaces)
	symbols[0], symbols[1] = symbolToHostEp, symbolFromHostEp
	directions[0], directions[1] = dirIngress, dirEgress
	objPaths[0], objPaths[1] = objPath, objPath
	interfaceNames[0], interfaceNames[1] = ep.InterfaceName(), ep.InterfaceName()

	nodePortIPv4Addrs := node.GetNodePortIPv4AddrsWithDevices()
	nodePortIPv6Addrs := node.GetNodePortIPv6AddrsWithDevices()

	for _, device := range option.Config.Devices {
		if _, err := netlink.LinkByName(device); err != nil {
			log.WithError(err).WithField("device", device).Warn("Link does not exist")
			continue
		}

		netdevObjPath := path.Join(ep.StateDir(), hostEndpointNetdevPrefix+device+".o")
		if err := patchHostNetdevDatapath(ep, objPath, netdevObjPath, device, nodePortIPv4Addrs, nodePortIPv6Addrs); err != nil {
			return err
		}
		objPaths = append(objPaths, netdevObjPath)

		interfaceNames = append(interfaceNames, device)
		symbols = append(symbols, symbolFromHostNetdevEp)
		directions = append(directions, dirIngress)
		if option.Config.EnableNodePort || option.Config.EnableHostFirewall {
			interfaceNames = append(interfaceNames, device)
			symbols = append(symbols, symbolToHostNetdevEp)
			directions = append(directions, dirEgress)
			objPaths = append(objPaths, netdevObjPath)
		} else {
			// Remove any previously attached device from egress path if BPF
			// NodePort is disabled.
			l.DeleteDatapath(ctx, device, dirEgress)
		}
	}

	for i, interfaceName := range interfaceNames {
		symbol := symbols[i]
		if err := l.replaceDatapath(ctx, interfaceName, objPaths[i], symbol, directions[i]); err != nil {
			scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
				logfields.Path: objPath,
				logfields.Veth: interfaceName,
			})
			// Don't log an error here if the context was canceled or timed out;
			// this log message should only represent failures with respect to
			// loading the program.
			if ctx.Err() == nil {
				scopedLog.WithError(err).Warningf("JoinEP: Failed to load program for host endpoint (%s)", symbol)
			}
			return err
		}
	}

	return nil
}

func (l *Loader) reloadDatapath(ctx context.Context, ep datapath.Endpoint, dirs *directoryInfo) error {
	// Replace the current program
	objPath := path.Join(dirs.Output, endpointObj)

	if ep.IsHost() {
		objPath = path.Join(dirs.Output, hostEndpointObj)
		if err := l.reloadHostDatapath(ctx, ep, objPath); err != nil {
			return err
		}
	} else if ep.HasIpvlanDataPath() {
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
	err := compileDatapath(ctx, dirs, ep.IsHost(), debug, ep.Logger(Subsystem))
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
	epObj := endpointObj
	if ep.IsHost() {
		epObj = hostEndpointObj
	}
	dstPath := path.Join(ep.StateDir(), epObj)
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
	return bpf.LocalMapPath(callsmap.MapName, id)
}
