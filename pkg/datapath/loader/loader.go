// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

const (
	Subsystem = "datapath-loader"

	symbolFromEndpoint = "from-container"
	symbolToEndpoint   = "to-container"
	symbolFromNetwork  = "from-network"

	symbolFromHostNetdevEp = "from-netdev"
	symbolToHostNetdevEp   = "to-netdev"
	symbolFromHostEp       = "from-host"
	symbolToHostEp         = "to-host"

	dirIngress = "ingress"
	dirEgress  = "egress"
)

const (
	SecctxFromIpcacheDisabled = iota + 1
	SecctxFromIpcacheEnabled
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

	return route.Upsert(endpointRoute)
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
	bpfMasqIPv4Addrs map[string]net.IP) error {

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
	if mac == nil {
		// L2-less device
		mac = make([]byte, 6)
		opts["ETH_HLEN"] = uint32(0)
	}
	opts["NODE_MAC_1"] = sliceToBe32(mac[0:4])
	opts["NODE_MAC_2"] = uint32(sliceToBe16(mac[4:6]))

	ifIndex, err := link.GetIfIndex(ifName)
	if err != nil {
		return err
	}

	if !option.Config.EnableHostLegacyRouting ||
		option.Config.DatapathMode == datapathOption.DatapathModeIpvlan {
		opts["SECCTX_FROM_IPCACHE"] = uint32(SecctxFromIpcacheEnabled)
	} else {
		opts["SECCTX_FROM_IPCACHE"] = uint32(SecctxFromIpcacheDisabled)
	}

	if option.Config.EnableNodePort {
		opts["NATIVE_DEV_IFINDEX"] = ifIndex
	}
	if option.Config.EnableIPv4Masquerade && option.Config.EnableBPFMasquerade && bpfMasqIPv4Addrs != nil {
		if option.Config.EnableIPv4 {
			ipv4 := bpfMasqIPv4Addrs[ifName]
			opts["IPV4_MASQUERADE"] = byteorder.NetIPv4ToHost32(ipv4)
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
	nbInterfaces := len(option.Config.GetDevices()) + 2
	symbols := make([]string, 2, nbInterfaces)
	directions := make([]string, 2, nbInterfaces)
	objPaths := make([]string, 2, nbInterfaces)
	interfaceNames := make([]string, 2, nbInterfaces)
	symbols[0], symbols[1] = symbolToHostEp, symbolFromHostEp
	directions[0], directions[1] = dirIngress, dirEgress
	objPaths[0], objPaths[1] = objPath, objPath
	interfaceNames[0], interfaceNames[1] = ep.InterfaceName(), ep.InterfaceName()

	if datapathHasMultipleMasterDevices() {
		if _, err := netlink.LinkByName(defaults.SecondHostDevice); err != nil {
			log.WithError(err).WithField("device", defaults.SecondHostDevice).Error("Link does not exist")
			return err
		} else {
			interfaceNames = append(interfaceNames, defaults.SecondHostDevice)
			symbols = append(symbols, symbolToHostEp)
			directions = append(directions, dirIngress)
			secondDevObjPath := path.Join(ep.StateDir(), hostEndpointPrefix+"_"+defaults.SecondHostDevice+".o")
			if err := patchHostNetdevDatapath(ep, objPath, secondDevObjPath, defaults.SecondHostDevice, nil); err != nil {
				return err
			}
			objPaths = append(objPaths, secondDevObjPath)
		}
	}

	bpfMasqIPv4Addrs := node.GetMasqIPv4AddrsWithDevices()

	for _, device := range option.Config.GetDevices() {
		if _, err := netlink.LinkByName(device); err != nil {
			log.WithError(err).WithField("device", device).Warn("Link does not exist")
			continue
		}

		netdevObjPath := path.Join(ep.StateDir(), hostEndpointNetdevPrefix+device+".o")
		if err := patchHostNetdevDatapath(ep, objPath, netdevObjPath, device, bpfMasqIPv4Addrs); err != nil {
			return err
		}
		objPaths = append(objPaths, netdevObjPath)

		interfaceNames = append(interfaceNames, device)
		symbols = append(symbols, symbolFromHostNetdevEp)
		directions = append(directions, dirIngress)
		if option.Config.EnableNodePort || option.Config.EnableHostFirewall ||
			option.Config.EnableBandwidthManager {
			interfaceNames = append(interfaceNames, device)
			symbols = append(symbols, symbolToHostNetdevEp)
			directions = append(directions, dirEgress)
			objPaths = append(objPaths, netdevObjPath)
		} else {
			// Remove any previously attached device from egress path if BPF
			// NodePort and host firewall are disabled.
			err := RemoveTCFilters(device, netlink.HANDLE_MIN_EGRESS)
			if err != nil {
				log.WithField("device", device).Error(err)
			}
		}
	}

	for i, interfaceName := range interfaceNames {
		symbol := symbols[i]
		finalize, err := replaceDatapath(ctx, interfaceName, objPaths[i], symbol, directions[i], false, "")
		if err != nil {
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
		// Defer map removal until all interfaces' progs have been replaced.
		defer finalize()
	}

	return nil
}

func datapathHasMultipleMasterDevices() bool {
	// When using ipvlan, HOST_DEV2 is equal to HOST_DEV1 in init.sh and we
	// have a single master device.
	return option.Config.DatapathMode != datapathOption.DatapathModeIpvlan
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
		finalize, err := replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint, dirIngress, false, "")
		if err != nil {
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
		defer finalize()

		if ep.RequireEgressProg() {
			finalize, err := replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolToEndpoint, dirEgress, false, "")
			if err != nil {
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
			defer finalize()
		} else {
			err := RemoveTCFilters(ep.InterfaceName(), netlink.HANDLE_MIN_EGRESS)
			if err != nil {
				log.WithField("device", ep.InterfaceName()).Error(err)
			}
		}
	}

	if ep.RequireEndpointRoute() {
		scopedLog := ep.Logger(Subsystem).WithFields(logrus.Fields{
			logfields.Veth: ep.InterfaceName(),
		})
		if ip := ep.IPv4Address(); ip.IsSet() {
			if err := upsertEndpointRoute(ep, *ip.EndpointPrefix()); err != nil {
				scopedLog.WithError(err).Warn("Failed to upsert route")
			}
		}
		if ip := ep.IPv6Address(); ip.IsSet() {
			if err := upsertEndpointRoute(ep, *ip.EndpointPrefix()); err != nil {
				scopedLog.WithError(err).Warn("Failed to upsert route")
			}
		}
	}

	return nil
}

func (l *Loader) replaceNetworkDatapath(ctx context.Context, interfaces []string) error {
	if err := compileNetwork(ctx); err != nil {
		log.WithError(err).Fatal("failed to compile encryption programs")
	}
	for _, iface := range option.Config.EncryptInterface {
		finalize, err := replaceDatapath(ctx, iface, networkObj, symbolFromNetwork, dirIngress, false, "")
		if err != nil {
			log.WithField(logfields.Interface, iface).WithError(err).Fatal("Load encryption network failed")
		}
		// Defer map removal until all interfaces' progs have been replaced.
		defer finalize()
	}
	return nil
}

func (l *Loader) compileAndLoad(ctx context.Context, ep datapath.Endpoint, dirs *directoryInfo, stats *metrics.SpanStat) error {
	stats.BpfCompilation.Start()
	err := compileDatapath(ctx, dirs, ep.IsHost(), ep.Logger(Subsystem))
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
			removeEndpointRoute(ep, *ip.EndpointPrefix())
		}

		if ip := ep.IPv6Address(); ip.IsSet() {
			removeEndpointRoute(ep, *ip.EndpointPrefix())
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

// CustomCallsMapPath gets the BPF Custom Calls Map for the endpoint with the
// specified ID.
func (l *Loader) CustomCallsMapPath(id uint16) string {
	return bpf.LocalMapPath(callsmap.CustomCallsMapName, id)
}
