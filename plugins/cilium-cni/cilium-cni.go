// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Ensure build fails on versions of Go that are not supported by Cilium.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.17

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"

	"github.com/cilium/ebpf"
	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	gops "github.com/google/gops/agent"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/hooks"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/version"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	_ "github.com/cilium/cilium/plugins/cilium-cni/chaining/awscni"
	_ "github.com/cilium/cilium/plugins/cilium-cni/chaining/azure"
	_ "github.com/cilium/cilium/plugins/cilium-cni/chaining/flannel"
	_ "github.com/cilium/cilium/plugins/cilium-cni/chaining/generic-veth"
	_ "github.com/cilium/cilium/plugins/cilium-cni/chaining/portmap"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

const (
	// defaultLogMaxBackups is to make sure that we have an upper bound on disk space used by
	// CNI file logging (e.g. < 7 * 100 MB).
	defaultLogMaxBackups = 7
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-cni")
)

func init() {
	runtime.LockOSThread()
}

type CmdState struct {
	Endpoint  *models.EndpointChangeRequest
	IP6       addressing.CiliumIPv6
	IP6routes []route.Route
	IP4       addressing.CiliumIPv4
	IP4routes []route.Route
	Client    *client.Client
	HostAddr  *models.NodeAddressing
}

func main() {
	skel.PluginMain(cmdAdd,
		nil,
		cmdDel,
		cniVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0"),
		"Cilium CNI plugin "+version.Version)
}

func ipv6IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV6 == "" {
		return false
	}

	if ipam.HostAddressing != nil && ipam.HostAddressing.IPV6 != nil {
		return ipam.HostAddressing.IPV6.Enabled
	}

	return true
}

func ipv4IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV4 == "" {
		return false
	}

	if ipam.HostAddressing != nil && ipam.HostAddressing.IPV4 != nil {
		return ipam.HostAddressing.IPV4.Enabled
	}

	return true
}

func getConfigFromCiliumAgent(client *client.Client) (*models.DaemonConfigurationStatus, error) {
	configResult, err := client.ConfigGet()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve configuration from cilium-agent: %w", err)
	}

	if configResult == nil || configResult.Status == nil {
		return nil, fmt.Errorf("received empty configuration object from cilium-agent")
	}

	return configResult.Status, nil
}

func allocateIPsWithCiliumAgent(client *client.Client, cniArgs types.ArgsSpec) (*models.IPAMResponse, func(context.Context), error) {
	podName := string(cniArgs.K8S_POD_NAMESPACE) + "/" + string(cniArgs.K8S_POD_NAME)
	ipam, err := client.IPAMAllocate("", podName, true)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to allocate IP via local cilium agent: %w", err)
	}

	if ipam.Address == nil {
		return nil, nil, fmt.Errorf("Invalid IPAM response, missing addressing")
	}

	releaseFunc := func(context.Context) {
		if ipam.Address != nil {
			releaseIP(client, ipam.Address.IPV4)
			releaseIP(client, ipam.Address.IPV6)
		}
	}

	return ipam, releaseFunc, nil
}

func releaseIP(client *client.Client, ip string) {
	if ip != "" {
		if err := client.IPAMReleaseIP(ip); err != nil {
			log.WithError(err).WithField(logfields.IPAddr, ip).Warn("Unable to release IP")
		}
	}
}

func allocateIPsWithDelegatedPlugin(
	ctx context.Context,
	conf *models.DaemonConfigurationStatus,
	netConf *types.NetConf,
	stdinData []byte,
) (*models.IPAMResponse, func(context.Context), error) {
	ipamRawResult, err := cniInvoke.DelegateAdd(ctx, netConf.IPAM.Type, stdinData, nil)
	if err != nil {
		// Since IP allocation failed, there are no IPs to clean up, so we don't need to return a releaseFunc.
		return nil, nil, fmt.Errorf("failed to invoke delegated plugin ADD for IPAM: %w", err)
	}

	// CNI spec says if an error occurs, invoke DEL on the delegated plugin to release IPs.
	releaseFunc := func(ctx context.Context) {
		cniInvoke.DelegateDel(ctx, netConf.IPAM.Type, stdinData, nil)
	}

	ipamResult, err := cniTypesVer.NewResultFromResult(ipamRawResult)
	if err != nil {
		return nil, releaseFunc, fmt.Errorf("could not interpret delegated IPAM result for CNI version %s: %w", cniTypesVer.ImplementedSpecVersion, err)
	}

	// Translate the IPAM result into the same format as a response from Cilium agent.
	ipam := &models.IPAMResponse{
		HostAddressing: conf.Addressing,
		Address:        &models.AddressPair{},
	}

	// Safe to assume at most one IP per family. The K8s API docs say:
	// "Pods may be allocated at most 1 value for each of IPv4 and IPv6"
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/
	for _, ipConfig := range ipamResult.IPs {
		ipNet := ipConfig.Address
		if ipv4 := ipNet.IP.To4(); ipv4 != nil {
			ipam.Address.IPV4 = ipNet.String()
			ipam.IPV4 = &models.IPAMAddressResponse{IP: ipv4.String()}
		} else {
			ipam.Address.IPV6 = ipNet.String()
			ipam.IPV6 = &models.IPAMAddressResponse{IP: ipNet.IP.String()}
		}
	}

	return ipam, releaseFunc, nil
}

func addIPConfigToLink(ip addressing.CiliumIP, routes []route.Route, link netlink.Link, ifName string) error {
	log.WithFields(logrus.Fields{
		logfields.IPAddr:    ip,
		"netLink":           logfields.Repr(link),
		logfields.Interface: ifName,
	}).Debug("Configuring link")

	addr := &netlink.Addr{IPNet: ip.EndpointPrefix()}
	if ip.IsIPv6() {
		addr.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add addr to %q: %v", ifName, err)
	}

	// ipvlan needs to be UP before we add routes, and can only be UPed after
	// we added an IP address.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	// Sort provided routes to make sure we apply any more specific
	// routes first which may be used as nexthops in wider routes
	sort.Sort(route.ByMask(routes))

	for _, r := range routes {
		log.WithField("route", logfields.Repr(r)).Debug("Adding route")
		rt := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       &r.Prefix,
			MTU:       r.MTU,
		}

		if r.Nexthop == nil {
			rt.Scope = netlink.SCOPE_LINK
		} else {
			rt.Gw = *r.Nexthop
		}

		if err := netlink.RouteAdd(rt); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%s via %v dev %v': %v",
					r.Prefix.String(), r.Nexthop, ifName, err)
			}
		}
	}

	return nil
}

func configureIface(ipam *models.IPAMResponse, ifName string, state *CmdState) (string, error) {
	l, err := netlink.LinkByName(ifName)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(l); err != nil {
		return "", fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	if ipv4IsEnabled(ipam) {
		if err := addIPConfigToLink(state.IP4, state.IP4routes, l, ifName); err != nil {
			return "", fmt.Errorf("error configuring IPv4: %s", err.Error())
		}
	}

	if ipv6IsEnabled(ipam) {
		if err := addIPConfigToLink(state.IP6, state.IP6routes, l, ifName); err != nil {
			return "", fmt.Errorf("error configuring IPv6: %s", err.Error())
		}
	}

	if err := netlink.LinkSetUp(l); err != nil {
		return "", fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	if l.Attrs() != nil {
		return l.Attrs().HardwareAddr.String(), nil
	}

	return "", nil
}

func newCNIRoute(r route.Route) *cniTypes.Route {
	rt := &cniTypes.Route{
		Dst: r.Prefix,
	}
	if r.Nexthop != nil {
		rt.GW = *r.Nexthop
	}

	return rt
}

func prepareIP(ipAddr string, isIPv6 bool, state *CmdState, mtu int) (*cniTypesVer.IPConfig, []*cniTypes.Route, error) {
	var (
		routes []route.Route
		err    error
		gw     string
		ip     addressing.CiliumIP
	)

	if isIPv6 {
		if state.IP6, err = addressing.NewCiliumIPv6(ipAddr); err != nil {
			return nil, nil, err
		}
		if state.IP6routes, err = connector.IPv6Routes(state.HostAddr, mtu); err != nil {
			return nil, nil, err
		}
		routes = state.IP6routes
		ip = state.IP6
		gw = connector.IPv6Gateway(state.HostAddr)
	} else {
		if state.IP4, err = addressing.NewCiliumIPv4(ipAddr); err != nil {
			return nil, nil, err
		}
		if state.IP4routes, err = connector.IPv4Routes(state.HostAddr, mtu); err != nil {
			return nil, nil, err
		}
		routes = state.IP4routes
		ip = state.IP4
		gw = connector.IPv4Gateway(state.HostAddr)
	}

	rt := []*cniTypes.Route{}
	for _, r := range routes {
		rt = append(rt, newCNIRoute(r))
	}

	gwIP := net.ParseIP(gw)
	if gwIP == nil {
		return nil, nil, fmt.Errorf("Invalid gateway address: %s", gw)
	}

	return &cniTypesVer.IPConfig{
		Address: *ip.EndpointPrefix(),
		Gateway: gwIP,
	}, rt, nil
}

func setupLogging(n *types.NetConf) error {
	f := n.LogFormat
	if f == "" {
		f = string(logging.DefaultLogFormat)
	}
	logOptions := logging.LogOptions{
		logging.FormatOpt: f,
	}
	err := logging.SetupLogging([]string{}, logOptions, "cilium-cni", n.EnableDebug)
	if err != nil {
		return err
	}

	if len(n.LogFile) != 0 {
		logging.AddHooks(hooks.NewFileRotationLogHook(n.LogFile,
			hooks.EnableCompression(),
			hooks.WithMaxBackups(defaultLogMaxBackups),
		))
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) (err error) {
	var (
		ipConfig *cniTypesVer.IPConfig
		routes   []*cniTypes.Route
		ipam     *models.IPAMResponse
		n        *types.NetConf
		c        *client.Client
		netNs    ns.NetNS
		conf     *models.DaemonConfigurationStatus
	)

	n, err = types.LoadNetConf(args.StdinData)
	if err != nil {
		err = fmt.Errorf("unable to parse CNI configuration \"%s\": %s", args.StdinData, err)
		return
	}

	if innerErr := setupLogging(n); innerErr != nil {
		err = fmt.Errorf("unable to setup logging: %w", innerErr)
		return
	}

	logger := log.WithField("eventUUID", uuid.New())

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			log.WithError(err).Warn("Unable to start gops")
		} else {
			defer gops.Close()
		}
	}
	logger.Debugf("Processing CNI ADD request %#v", args)

	logger.Debugf("CNI NetConf: %#v", n)
	if n.PrevResult != nil {
		logger.Debugf("CNI Previous result: %#v", n.PrevResult)
	}

	cniArgs := types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, &cniArgs); err != nil {
		err = fmt.Errorf("unable to extract CNI arguments: %s", err)
		return
	}
	logger.Debugf("CNI Args: %#v", cniArgs)

	c, err = client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		err = fmt.Errorf("unable to connect to Cilium daemon: %s", client.Hint(err))
		return
	}

	if len(n.NetConf.RawPrevResult) != 0 && n.Name != chainingapi.DefaultConfigName {
		if chainAction := chainingapi.Lookup(n.Name); chainAction != nil {
			var (
				res *cniTypesVer.Result
				ctx = chainingapi.PluginContext{
					Logger:  logger,
					Args:    args,
					CniArgs: cniArgs,
					NetConf: n,
					Client:  c,
				}
			)

			if chainAction.ImplementsAdd() {
				res, err = chainAction.Add(context.TODO(), ctx)
				if err != nil {
					return
				}
				logger.Debugf("Returning result %#v", res)
				err = cniTypes.PrintResult(res, n.CNIVersion)
				return
			}
		} else {
			logger.Warnf("Unknown CNI chaining configuration name '%s'", n.Name)
		}
	}

	netNs, err = ns.GetNS(args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %s", args.Netns, err)
		return
	}
	defer netNs.Close()

	if err = netns.RemoveIfFromNetNSIfExists(netNs, args.IfName); err != nil {
		err = fmt.Errorf("failed removing interface %q from namespace %q: %s",
			args.IfName, args.Netns, err)
		return
	}

	addLabels := models.Labels{}

	conf, err = getConfigFromCiliumAgent(c)
	if err != nil {
		return
	}

	var releaseIPsFunc func(context.Context)
	if conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
		ipam, releaseIPsFunc, err = allocateIPsWithDelegatedPlugin(context.TODO(), conf, n, args.StdinData)
	} else {
		ipam, releaseIPsFunc, err = allocateIPsWithCiliumAgent(c, cniArgs)
	}

	// release addresses on failure
	defer func() {
		if err != nil && releaseIPsFunc != nil {
			releaseIPsFunc(context.TODO())
		}
	}()

	if err != nil {
		return
	}

	if err = connector.SufficientAddressing(ipam.HostAddressing); err != nil {
		err = fmt.Errorf("IP allocation addressing in insufficient: %s", err)
		return
	}

	ep := &models.EndpointChangeRequest{
		ContainerID:           args.ContainerID,
		Labels:                addLabels,
		State:                 models.EndpointStateWaitingForIdentity,
		Addressing:            &models.AddressPair{},
		K8sPodName:            string(cniArgs.K8S_POD_NAME),
		K8sNamespace:          string(cniArgs.K8S_POD_NAMESPACE),
		DatapathConfiguration: &models.EndpointDatapathConfiguration{},
	}

	if conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
		// Prevent cilium agent from trying to release the IP when the endpoint is deleted.
		ep.DatapathConfiguration.ExternalIpam = true
	}

	switch conf.DatapathMode {
	case datapathOption.DatapathModeVeth:
		var (
			veth      *netlink.Veth
			peer      netlink.Link
			tmpIfName string
		)
		veth, peer, tmpIfName, err = connector.SetupVeth(ep.ContainerID, int(conf.DeviceMTU), ep)
		if err != nil {
			err = fmt.Errorf("unable to set up veth on host side: %s", err)
			return err
		}
		defer func() {
			if err != nil {
				if err2 := netlink.LinkDel(veth); err2 != nil {
					logger.WithError(err2).WithField(logfields.Veth, veth.Name).Warn("failed to clean up and delete veth")
				}
			}
		}()

		if err = netlink.LinkSetNsFd(peer, int(netNs.Fd())); err != nil {
			err = fmt.Errorf("unable to move veth pair '%v' to netns: %s", peer, err)
			return
		}

		_, _, err = connector.SetupVethRemoteNs(netNs, tmpIfName, args.IfName)
		if err != nil {
			err = fmt.Errorf("unable to set up veth on container side: %s", err)
			return
		}
	case datapathOption.DatapathModeIpvlan:
		ipvlanConf := *conf.IpvlanConfiguration
		index := int(ipvlanConf.MasterDeviceIndex)

		var m *ebpf.Map
		m, err = connector.CreateAndSetupIpvlanSlave(
			ep.ContainerID, args.IfName, netNs,
			int(conf.DeviceMTU), index, ipvlanConf.OperationMode, ep,
		)
		if err != nil {
			err = fmt.Errorf("unable to setup ipvlan datapath: %s", err)
			return
		}
		defer m.Close()
	}

	state := CmdState{
		Endpoint: ep,
		Client:   c,
		HostAddr: ipam.HostAddressing,
	}

	res := &cniTypesVer.Result{}

	if !ipv6IsEnabled(ipam) && !ipv4IsEnabled(ipam) {
		err = fmt.Errorf("IPAM did not provide IPv4 or IPv6 address")
		return
	}

	if ipv6IsEnabled(ipam) {
		ep.Addressing.IPV6 = ipam.Address.IPV6
		ep.Addressing.IPV6ExpirationUUID = ipam.IPV6.ExpirationUUID

		ipConfig, routes, err = prepareIP(ep.Addressing.IPV6, true, &state, int(conf.RouteMTU))
		if err != nil {
			err = fmt.Errorf("unable to prepare IP addressing for '%s': %s", ep.Addressing.IPV6, err)
			return
		}
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
	}

	if ipv4IsEnabled(ipam) {
		ep.Addressing.IPV4 = ipam.Address.IPV4
		ep.Addressing.IPV4ExpirationUUID = ipam.IPV4.ExpirationUUID

		ipConfig, routes, err = prepareIP(ep.Addressing.IPV4, false, &state, int(conf.RouteMTU))
		if err != nil {
			err = fmt.Errorf("unable to prepare IP addressing for '%s': %s", ep.Addressing.IPV4, err)
			return
		}
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
	}

	switch conf.IpamMode {
	case ipamOption.IPAMENI, ipamOption.IPAMAzure, ipamOption.IPAMAlibabaCloud:
		err = interfaceAdd(ipConfig, ipam.IPV4, conf)
		if err != nil {
			err = fmt.Errorf("unable to setup interface datapath: %s", err)
			return
		}
	}

	var macAddrStr string
	if err = netNs.Do(func(_ ns.NetNS) error {
		if ipv6IsEnabled(ipam) {
			if err := sysctl.Disable("net.ipv6.conf.all.disable_ipv6"); err != nil {
				logger.WithError(err).Warn("unable to enable ipv6 on all interfaces")
			}
		}
		macAddrStr, err = configureIface(ipam, args.IfName, &state)
		return err
	}); err != nil {
		err = fmt.Errorf("unable to configure interfaces in container namespace: %s", err)
		return
	}

	res.Interfaces = append(res.Interfaces, &cniTypesVer.Interface{
		Name:    args.IfName,
		Mac:     macAddrStr,
		Sandbox: args.Netns,
	})

	// Add to the result the Interface as index of Interfaces
	for i := range res.Interfaces {
		res.IPs[i].Interface = cniTypesVer.Int(i)
	}

	// Specify that endpoint must be regenerated synchronously. See GH-4409.
	ep.SyncBuildEndpoint = true
	if err = c.EndpointCreate(ep); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			logfields.ContainerID: ep.ContainerID}).Warn("Unable to create endpoint")
		err = fmt.Errorf("Unable to create endpoint: %s", err)
		return
	}

	logger.WithFields(logrus.Fields{
		logfields.ContainerID: ep.ContainerID}).Debug("Endpoint successfully created")
	return cniTypes.PrintResult(res, n.CNIVersion)
}

// cmdDel is invoked on CNI DEL
//
// Note: ENI specific attributes do not need to be released as the ENIs and ENI
// IPs can be reused and are not released until the node terminates.
func cmdDel(args *skel.CmdArgs) error {
	// Note about when to return errors: kubelet will retry the deletion
	// for a long time. Therefore, only return an error for errors which
	// are guaranteed to be recoverable.
	n, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		err = fmt.Errorf("unable to parse CNI configuration \"%s\": %s", args.StdinData, err)
		return err
	}

	if err := setupLogging(n); err != nil {
		return fmt.Errorf("unable to setup logging: %w", err)
	}

	logger := log.WithField("eventUUID", uuid.New())

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			log.WithError(err).Warn("Unable to start gops")
		} else {
			defer gops.Close()
		}
	}
	logger.Debugf("Processing CNI DEL request %#v", args)

	logger.Debugf("CNI NetConf: %#v", n)

	cniArgs := types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, &cniArgs); err != nil {
		return fmt.Errorf("unable to extract CNI arguments: %s", err)
	}
	logger.Debugf("CNI Args: %#v", cniArgs)

	c, err := client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		// this error can be recovered from
		return fmt.Errorf("unable to connect to Cilium daemon: %s", client.Hint(err))
	}

	conf, err := getConfigFromCiliumAgent(c)
	if err != nil {
		return err
	}

	if n.Name != chainingapi.DefaultConfigName {
		if chainAction := chainingapi.Lookup(n.Name); chainAction != nil {
			var (
				ctx = chainingapi.PluginContext{
					Logger:  logger,
					Args:    args,
					CniArgs: cniArgs,
					NetConf: n,
					Client:  c,
				}
			)

			if chainAction.ImplementsDelete() {
				return chainAction.Delete(context.TODO(), ctx)
			}
		} else {
			logger.Warnf("Unknown CNI chaining configuration name '%s'", n.Name)
		}
	}

	id := endpointid.NewID(endpointid.ContainerIdPrefix, args.ContainerID)
	if err := c.EndpointDelete(id); err != nil {
		// EndpointDelete returns an error in the following scenarios:
		// DeleteEndpointIDInvalid: Invalid delete parameters, no need to retry
		// DeleteEndpointIDNotFound: No need to retry
		// DeleteEndpointIDErrors: Errors encountered while deleting,
		//                         the endpoint is always deleted though, no
		//                         need to retry
		log.WithError(err).Warning("Errors encountered while deleting endpoint")
	}

	netNs, err := ns.GetNS(args.Netns)
	if err != nil {
		log.WithError(err).Warningf("Unable to enter namespace %q, will not delete interface", args.Netns)
		// We are not returning an error as this is very unlikely to be recoverable
		return nil
	}
	defer netNs.Close()

	err = netns.RemoveIfFromNetNSIfExists(netNs, args.IfName)
	if err != nil {
		log.WithError(err).Warningf("Unable to delete interface %s in namespace %q, will not delete interface", args.IfName, args.Netns)
		// We are not returning an error as this is very unlikely to be recoverable
	}

	if conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
		err = cniInvoke.DelegateDel(context.TODO(), n.IPAM.Type, args.StdinData, nil)
		if err != nil {
			return err
		}
	}

	return nil
}
