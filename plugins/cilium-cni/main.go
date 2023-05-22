// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"

	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	gops "github.com/google/gops/agent"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	iputil "github.com/cilium/cilium/pkg/ip"
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
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
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
	IP6       netip.Addr
	IP6routes []route.Route
	IP4       netip.Addr
	IP4routes []route.Route
	Client    *client.Client
	HostAddr  *models.NodeAddressing
}

func main() {
	skel.PluginMain(cmdAdd,
		cmdCheck,
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

	ipam, err := client.IPAMAllocate("", podName, "", true)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to allocate IP via local cilium agent: %w", err)
	}

	if ipam.Address == nil {
		return nil, nil, fmt.Errorf("invalid IPAM response, missing addressing")
	}

	releaseFunc := func(context.Context) {
		if ipam.Address != nil {
			releaseIP(client, ipam.Address.IPV4, ipam.Address.IPV4PoolName)
			releaseIP(client, ipam.Address.IPV6, ipam.Address.IPV6PoolName)
		}
	}

	return ipam, releaseFunc, nil
}

func releaseIP(client *client.Client, ip, pool string) {
	if ip != "" {
		if err := client.IPAMReleaseIP(ip, pool); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr: ip,
				"pool":           pool,
			}).Warn("Unable to release IP")
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

	ipamResult, err := cniTypesV1.NewResultFromResult(ipamRawResult)
	if err != nil {
		return nil, releaseFunc, fmt.Errorf("could not interpret delegated IPAM result for CNI version %s: %w", cniTypesV1.ImplementedSpecVersion, err)
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

func addIPConfigToLink(ip netip.Addr, routes []route.Route, link netlink.Link, ifName string) error {
	log.WithFields(logrus.Fields{
		logfields.IPAddr:    ip,
		"netLink":           logfields.Repr(link),
		logfields.Interface: ifName,
	}).Debug("Configuring link")

	addr := &netlink.Addr{IPNet: iputil.AddrToIPNet(ip)}
	if ip.Is6() {
		addr.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add addr to %q: %w", ifName, err)
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

func prepareIP(ipAddr string, state *CmdState, mtu int) (*cniTypesV1.IPConfig, []*cniTypes.Route, error) {
	var (
		routes []route.Route
		gw     string
		ip     netip.Addr
	)

	// This handles both scenarios for handling IPaddress as CIDR as well as IPaddress
	// from delegated Ipam and cilium-agent
	ipPrefix, err := netip.ParsePrefix(ipAddr)
	if err != nil {
		ip, err = netip.ParseAddr(ipAddr)
	} else {
		ip = ipPrefix.Addr()
	}

	if err != nil {
		return nil, nil, err
	}

	if ip.Is6() {
		state.IP6 = ip
		if state.IP6routes, err = connector.IPv6Routes(state.HostAddr, mtu); err != nil {
			return nil, nil, err
		}
		routes = state.IP6routes
		ip = state.IP6
		gw = connector.IPv6Gateway(state.HostAddr)
	} else {
		state.IP4 = ip
		if state.IP4routes, err = connector.IPv4Routes(state.HostAddr, mtu); err != nil {
			return nil, nil, err
		}
		routes = state.IP4routes
		ip = state.IP4
		gw = connector.IPv4Gateway(state.HostAddr)
	}

	rt := make([]*cniTypes.Route, 0, len(routes))
	for _, r := range routes {
		rt = append(rt, newCNIRoute(r))
	}

	gwIP := net.ParseIP(gw)
	if gwIP == nil {
		return nil, nil, fmt.Errorf("invalid gateway address: %s", gw)
	}

	return &cniTypesV1.IPConfig{
		Address: *iputil.AddrToIPNet(ip),
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
		ipConfig *cniTypesV1.IPConfig
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

	// If CNI ADD gives us a PrevResult, we're a chained plugin and *must* detect a
	// valid chained mode. If no chained mode we understand is specified, error out.
	// Otherwise, continue with normal plugin execution.
	if len(n.NetConf.RawPrevResult) != 0 {
		if chainAction, err := getChainedAction(n, logger); chainAction != nil {
			var (
				res *cniTypesV1.Result
				ctx = chainingapi.PluginContext{
					Logger:  logger,
					Args:    args,
					CniArgs: cniArgs,
					NetConf: n,
				}
			)

			res, err = chainAction.Add(context.TODO(), ctx, c)
			if err != nil {
				logger.WithError(err).Warn("Chained ADD failed")
				return err
			}
			logger.Debugf("Returning result %#v", res)
			return cniTypes.PrintResult(res, n.CNIVersion)
		} else if err != nil {
			logger.WithError(err).Error("Invalid chaining mode")
			return err
		} else {
			// no chained action supplied; this is an error
			logger.Error("CNI PrevResult supplied, but not in chaining mode -- this is invalid, please set chaining-mode in CNI configuration")
			return fmt.Errorf("CNI PrevResult supplied, but not in chaining mode -- this is invalid, please set chaining-mode in CNI configuration")
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
		State:                 models.EndpointStateWaitingDashForDashIdentity.Pointer(),
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
		veth, peer, tmpIfName, err = connector.SetupVeth(ep.ContainerID, int(conf.DeviceMTU), int(conf.GROMaxSize), int(conf.GSOMaxSize), ep)
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
	}

	state := CmdState{
		Endpoint: ep,
		Client:   c,
		HostAddr: ipam.HostAddressing,
	}

	res := &cniTypesV1.Result{}

	if !ipv6IsEnabled(ipam) && !ipv4IsEnabled(ipam) {
		err = fmt.Errorf("IPAM did not provide IPv4 or IPv6 address")
		return
	}

	if ipv6IsEnabled(ipam) {
		ep.Addressing.IPV6 = ipam.Address.IPV6
		ep.Addressing.IPV6PoolName = ipam.Address.IPV6PoolName
		ep.Addressing.IPV6ExpirationUUID = ipam.IPV6.ExpirationUUID

		ipConfig, routes, err = prepareIP(ep.Addressing.IPV6, &state, int(conf.RouteMTU))
		if err != nil {
			err = fmt.Errorf("unable to prepare IP addressing for '%s': %s", ep.Addressing.IPV6, err)
			return
		}
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
	}

	if ipv4IsEnabled(ipam) {
		ep.Addressing.IPV4 = ipam.Address.IPV4
		ep.Addressing.IPV4PoolName = ipam.Address.IPV4PoolName
		ep.Addressing.IPV4ExpirationUUID = ipam.IPV4.ExpirationUUID

		ipConfig, routes, err = prepareIP(ep.Addressing.IPV4, &state, int(conf.RouteMTU))
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

	res.Interfaces = append(res.Interfaces, &cniTypesV1.Interface{
		Name:    args.IfName,
		Mac:     macAddrStr,
		Sandbox: args.Netns,
	})

	// Add to the result the Interface as index of Interfaces
	for i := range res.Interfaces {
		res.IPs[i].Interface = cniTypesV1.Int(i)
	}

	// Specify that endpoint must be regenerated synchronously. See GH-4409.
	ep.SyncBuildEndpoint = true
	if err = c.EndpointCreate(ep); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			logfields.ContainerID: ep.ContainerID}).Warn("Unable to create endpoint")
		err = fmt.Errorf("unable to create endpoint: %s", err)
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

	logger = logger.WithField("containerID", args.ContainerID)

	c, err := lib.NewDeletionFallbackClient(logger)
	if err != nil {
		return fmt.Errorf("unable to connect to Cilium agent: %w", err)
	}

	// If this is a chained plugin, then "delegate" to the special chaining mode and be done.
	// Note: DEL always has PrevResult set, so that doesn't tell us if we're chained. Given
	// that a CNI ADD could not have succeeded with an invalid chained mode, we should always
	// find a valid chained mode
	if chainAction, err := getChainedAction(n, logger); chainAction != nil {
		var (
			ctx = chainingapi.PluginContext{
				Logger:  logger,
				Args:    args,
				CniArgs: cniArgs,
				NetConf: n,
			}
		)

		return chainAction.Delete(context.TODO(), ctx, c)
	} else if err != nil {
		logger.WithError(err).Error("Invalid chaining mode")
		return err
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

	if n.IPAM.Type != "" {
		// If using a delegated plugin for IPAM, attempt to release the IP.
		// We do this *before* entering the network namespace, because the ns may
		// have already been deleted, and we want to avoid leaking IPs.
		err = cniInvoke.DelegateDel(context.TODO(), n.IPAM.Type, args.StdinData, nil)
		if err != nil {
			return err
		}
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

	return nil
}

// cmdCheck implements the cni CHECK verb.
// It ensures that the interface is configured correctly
//
// Currently, it verifies that
// - endpoint exists in the agent and is healthy
// - the interface in the container is sane
func cmdCheck(args *skel.CmdArgs) error {
	n, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidNetworkConfig",
			fmt.Sprintf("unable to parse CNI configuration \"%s\": %s", args.StdinData, err))
	}

	if err := setupLogging(n); err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidLoggingConfig",
			fmt.Sprintf("unable to setup logging: %s", err))
	}

	logger := log.WithField("eventUUID", uuid.New())

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			log.WithError(err).Warn("Unable to start gops")
		} else {
			defer gops.Close()
		}
	}
	logger.Debugf("Processing CNI CHECK request %#v", args)

	logger.Debugf("CNI NetConf: %#v", n)
	if n.PrevResult != nil {
		logger.Debugf("CNI Previous result: %#v", n.PrevResult)
	}

	cniArgs := types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, &cniArgs); err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidArgs",
			fmt.Sprintf("unable to extract CNI arguments: %s", err))
	}
	logger.Debugf("CNI Args: %#v", cniArgs)

	c, err := client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		// use ErrTryAgainLater to tell the runtime that this is not a check failure
		return cniTypes.NewError(cniTypes.ErrTryAgainLater, "DaemonDown",
			fmt.Sprintf("unable to connect to Cilium daemon: %s", client.Hint(err)))
	}

	// If this is a chained plugin, then "delegate" to the special chaining mode and be done
	// Note: CHECK always has PrevResult set, so that doesn't tell us if we're chained.
	if chainAction, err := getChainedAction(n, logger); chainAction != nil {
		var (
			ctx = chainingapi.PluginContext{
				Logger:  logger,
				Args:    args,
				CniArgs: cniArgs,
				NetConf: n,
			}
		)

		// err is nil on success
		err := chainAction.Check(context.TODO(), ctx, c)
		logger.Debugf("Chained CHECK %s returned %s", n.Name, err)
		return err
	} else if err != nil {
		logger.WithError(err).Error("Invalid chaining mode")
		return err
	}

	// mechanical: parse PrevResult
	if err := cniVersion.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}
	prevResult, err := cniTypesV1.NewResultFromResult(n.NetConf.PrevResult)
	if err != nil {
		return err
	}

	netNs, err := ns.GetNS(args.Netns)
	if err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidEnvironmentVariables, "NoNetNS",
			fmt.Sprintf("failed to open netns %q: %s", args.Netns, err))
	}
	defer netNs.Close()

	// Ask the agent for the endpoint's health
	eID := fmt.Sprintf("container-id:%s", args.ContainerID)
	logger.Debugf("Asking agent for healthz for %s", eID)
	epHealth, err := c.EndpointHealthGet(eID)
	if err != nil {
		return cniTypes.NewError(types.CniErrHealthzGet, "HealthzFailed",
			fmt.Sprintf("failed to retrieve container health: %s", err))
	}

	if epHealth.OverallHealth == models.EndpointHealthStatusFailure {
		return cniTypes.NewError(types.CniErrUnhealthy, "Unhealthy",
			"container is unhealthy in agent")
	}
	logger.Debugf("Container %s has a healthy agent endpoint", args.ContainerID)

	// Verify that the interface exists and has the desired IP address
	// we can get the IP from the CNI previous result.
	if err := verifyInterface(netNs, args.IfName, prevResult); err != nil {
		return err
	}

	return nil
}

// verifyInterface verifies that a given interface exists in the netns
// with the given addresses
func verifyInterface(netns ns.NetNS, ifName string, expected *cniTypesV1.Result) error {
	wantAddresses := []*cniTypesV1.IPConfig{}
	for idx, iface := range expected.Interfaces {
		if iface.Sandbox == "" {
			continue
		}
		if iface.Name != ifName {
			continue
		}
		for _, ip := range expected.IPs {
			if ip.Interface != nil && *ip.Interface == idx {
				wantAddresses = append(wantAddresses, ip)
			}
		}
	}

	// Enter the container's namespace and ensure that
	// the interface looks good:
	// - does it exist?
	// - does it have the expected IPs?
	//
	// Possible future ideas:
	// - mtu
	// - routes
	return netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("cannot find container link %v", ifName)
		}

		addrList, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("failed to list link addresses: %w", err)
		}

		for _, ip := range wantAddresses {
			ourAddr := netlink.Addr{IPNet: &ip.Address}
			match := false

			for _, addr := range addrList {
				if addr.Equal(ourAddr) {
					match = true
					break
				}
			}
			if !match {
				return fmt.Errorf("expected ip %v on interface %v", ourAddr, ifName)
			}
		}

		return nil
	})
}

// getChainedAction retrieves the desired chained action. It returns nil if there
// is no chained action, and error if there is a configured chained action but it is
// invalid.
func getChainedAction(n *types.NetConf, logger *logrus.Entry) (chainingapi.ChainingPlugin, error) {
	if n.ChainingMode != "" {
		chainAction := chainingapi.Lookup(n.ChainingMode)
		if chainAction == nil {
			return nil, fmt.Errorf("invalid chaining-mode %s", n.ChainingMode)
		}

		logger.Infof("Using chained plugin %s", n.ChainingMode)
		return chainAction, nil
	}

	// Chained action can either be explicitly enabled, or implicitly based on
	// network name.
	// Portmap is a special case; we used it to signify that the portmap plugin
	// is included later in the chain, but we should treat it as a standard plugin.
	if n.Name != chainingapi.DefaultConfigName && n.Name != "portmap" {
		chainAction := chainingapi.Lookup(n.Name)
		if chainAction == nil {
			// In this case, we are just being called with a different network name;
			// there isn't any chaining happening.
			return nil, nil
		}

		logger.Infof("Using chained plugin %s", n.Name)
		return chainAction, nil
	}

	// OK to return nil, nil if chaining isn't enabled.
	return nil, nil
}
