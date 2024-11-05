// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"

	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	gops "github.com/google/gops/agent"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/hooks"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/netns"
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
	log            = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-cni")
	getNetnsCookie = true
)

// Cmd provides methods for the CNI ADD, DEL and CHECK commands.
type Cmd struct {
	cfg EndpointConfigurator
}

// Option allows the customization of the Cmd implementation
type Option func(cmd *Cmd)

// WithEPConfigurator is used to create a Cmd instance with a custom
// endpoint configurator. The endpoint configurator can be used to customize
// the creation of endpoints during the CNI ADD invocation.
// This function is exported to be accessed outside the tree.
func WithEPConfigurator(cfg EndpointConfigurator) Option {
	return func(cmd *Cmd) {
		cmd.cfg = cfg
	}
}

// NewCmd creates a new Cmd instance with Add, Del and Check methods
func NewCmd(opts ...Option) *Cmd {
	cmd := &Cmd{
		cfg: &DefaultConfigurator{},
	}
	for _, opt := range opts {
		opt(cmd)
	}
	return cmd
}

// CNIFuncs returns the CNI functions supported by Cilium that can be passed to skel.PluginMainFuncs
func (cmd *Cmd) CNIFuncs() skel.CNIFuncs {
	return skel.CNIFuncs{
		Add:   cmd.Add,
		Del:   cmd.Del,
		Check: cmd.Check,
	}
}

type CmdState struct {
	IP6       netip.Addr
	IP6routes []route.Route
	IP6rules  []route.Rule
	IP4       netip.Addr
	IP4routes []route.Route
	IP4rules  []route.Rule
	HostAddr  *models.NodeAddressing
}

func ipv6IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV6 == "" {
		return false
	}

	if ipam.HostAddressing == nil || ipam.HostAddressing.IPV6 == nil {
		return false
	}

	return ipam.HostAddressing.IPV6.Enabled
}

func ipv4IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV4 == "" {
		return false
	}

	if ipam.HostAddressing == nil || ipam.HostAddressing.IPV4 == nil {
		return false
	}

	return ipam.HostAddressing.IPV4.Enabled
}

func getConfigFromCiliumAgent(client *client.Client) (*models.DaemonConfigurationStatus, error) {
	configResult, err := client.ConfigGet()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve configuration from Cilium agent: %w", err)
	}

	if configResult == nil || configResult.Status == nil {
		return nil, errors.New("received empty configuration object from Cilium agent")
	}

	return configResult.Status, nil
}

func allocateIPsWithCiliumAgent(client *client.Client, cniArgs *types.ArgsSpec, ipamPoolName string) (*models.IPAMResponse, func(context.Context), error) {
	podName := string(cniArgs.K8S_POD_NAMESPACE) + "/" + string(cniArgs.K8S_POD_NAME)

	ipam, err := client.IPAMAllocate("", podName, ipamPoolName, true)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to allocate IP via local cilium agent: %w", err)
	}

	if ipam.Address == nil {
		return nil, nil, errors.New("invalid IPAM response, missing addressing")
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
		} else if conf.Addressing.IPV6 != nil {
			// assign ipam ipv6 address only if agent ipv6 config is enabled
			ipam.Address.IPV6 = ipNet.String()
			ipam.IPV6 = &models.IPAMAddressResponse{IP: ipNet.IP.String()}
		}
	}

	return ipam, releaseFunc, nil
}

func addIPConfigToLink(ip netip.Addr, routes []route.Route, rules []route.Rule, link netlink.Link, ifName string) error {
	log.WithFields(logrus.Fields{
		logfields.IPAddr:    ip,
		"netLink":           logfields.Repr(link),
		logfields.Interface: ifName,
	}).Debug("Configuring link")

	addr := &netlink.Addr{IPNet: netipx.AddrIPNet(ip)}
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
			Table:     r.Table,
		}

		if r.Nexthop == nil {
			rt.Scope = netlink.SCOPE_LINK
		} else {
			rt.Gw = *r.Nexthop
		}

		if err := netlink.RouteAdd(rt); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%s via %v dev %v': %w",
					r.Prefix.String(), r.Nexthop, ifName, err)
			}
		}
	}

	for _, r := range rules {
		log.WithField("rule", logfields.Repr(r)).Debug("Adding rule")
		var err error
		if ip.Is4() {
			err = route.ReplaceRule(r)
		} else {
			err = route.ReplaceRuleIPv6(r)
		}
		if err != nil {
			return fmt.Errorf("failed to add rule '%s for dev %v': %w", r, ifName, err)
		}
	}

	return nil
}

func configureIface(ipam *models.IPAMResponse, ifName string, state *CmdState) (string, error) {
	l, err := netlink.LinkByName(ifName)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %w", ifName, err)
	}

	if err := netlink.LinkSetUp(l); err != nil {
		return "", fmt.Errorf("failed to set %q UP: %w", ifName, err)
	}

	if ipv4IsEnabled(ipam) {
		if err := addIPConfigToLink(state.IP4, state.IP4routes, state.IP4rules, l, ifName); err != nil {
			return "", fmt.Errorf("error configuring IPv4: %w", err)
		}
	}

	if ipv6IsEnabled(ipam) {
		if err := addIPConfigToLink(state.IP6, state.IP6routes, state.IP6rules, l, ifName); err != nil {
			return "", fmt.Errorf("error configuring IPv6: %w", err)
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
		if state.HostAddr != nil {
			if routes, err = connector.IPv6Routes(state.HostAddr, mtu); err != nil {
				return nil, nil, err
			}
			state.IP6routes = append(state.IP6routes, routes...)
			gw = connector.IPv6Gateway(state.HostAddr)
		}
	} else {
		state.IP4 = ip
		if state.HostAddr != nil {
			if routes, err = connector.IPv4Routes(state.HostAddr, mtu); err != nil {
				return nil, nil, err
			}
			state.IP4routes = append(state.IP4routes, routes...)
			gw = connector.IPv4Gateway(state.HostAddr)
		}
	}

	rt := make([]*cniTypes.Route, 0, len(routes))
	for _, r := range routes {
		rt = append(rt, newCNIRoute(r))
	}

	var gwIP net.IP
	if gw != "" {
		gwIP = net.ParseIP(gw)
		if gwIP == nil {
			return nil, nil, fmt.Errorf("invalid gateway address: %s", gw)
		}
	}

	return &cniTypesV1.IPConfig{
		Address: *netipx.AddrIPNet(ip),
		Gateway: gwIP,
	}, rt, nil
}

func setupLogging(n *types.NetConf) error {
	f := n.LogFormat
	if f == "" {
		f = string(logging.DefaultLogFormatTimestamp)
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

func reserveLocalIPPorts(conf *models.DaemonConfigurationStatus, sysctl sysctl.Sysctl) error {
	if conf.IPLocalReservedPorts == "" {
		return nil
	}

	// Note: This setting applies to IPv4 and IPv6
	var (
		param    = []string{"net", "ipv4", "ip_local_reserved_ports"}
		reserved = conf.IPLocalReservedPorts
	)

	// Append our reserved ports to the ones which might already be reserved.
	existing, err := sysctl.Read(param)
	if err != nil {
		return err
	}

	// Merging the two sets of ports. Note that the kernel merges any redundant
	// ports or port ranges for us, so we do not have to check if `existing`
	// and `reserved` contain any overlapping ports.
	if existing != "" {
		reserved = existing + "," + reserved
	}
	return sysctl.Write(param, reserved)
}

func (cmd *Cmd) Add(args *skel.CmdArgs) (err error) {
	n, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("unable to parse CNI configuration %q: %w", string(args.StdinData), err)
	}

	if err = setupLogging(n); err != nil {
		return fmt.Errorf("unable to setup logging: %w", err)
	}

	logger := loggerWithArguments(log.WithField(logfields.EventUUID, uuid.New()), args)

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			log.WithError(err).Warn("Unable to start gops")
		} else {
			defer gops.Close()
		}
	}
	logger.WithField("netconf", logfields.Repr(n)).Debugf("Processing CNI ADD request")

	if n.PrevResult != nil {
		logger.WithField("previousResult", logfields.Repr(n.PrevResult)).Debugf("CNI Previous result")
	}

	cniArgs := &types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, cniArgs); err != nil {
		return fmt.Errorf("unable to extract CNI arguments: %w", err)
	}
	logger = loggerWithCNIArgs(logger, cniArgs)

	c, err := client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		return fmt.Errorf("unable to connect to Cilium agent: %w", client.Hint(err))
	}

	conf, err := getConfigFromCiliumAgent(c)
	if err != nil {
		return err
	}

	// If CNI ADD gives us a PrevResult, we're a chained plugin and *must* detect a
	// valid chained mode. If no chained mode we understand is specified, error out.
	// Otherwise, continue with normal plugin execution.
	if len(n.NetConf.RawPrevResult) != 0 {
		if chainAction, err := getChainedAction(n, logger); chainAction != nil {
			var (
				res *cniTypesV1.Result
				ctx = chainingapi.PluginContext{
					Logger:     logger,
					Args:       args,
					CniArgs:    cniArgs,
					NetConf:    n,
					CiliumConf: conf,
				}
			)

			res, err = chainAction.Add(context.TODO(), ctx, c)
			if err != nil {
				logger.WithError(err).Warn("Chained ADD failed")
				return err
			}
			logger.WithField("result", logfields.Repr(res)).Debugf("Returning result")
			return cniTypes.PrintResult(res, n.CNIVersion)
		} else if err != nil {
			logger.WithError(err).Error("Invalid chaining mode")
			return err
		} else {
			// no chained action supplied; this is an error
			logger.Error("CNI PrevResult supplied, but not in chaining mode -- this is invalid, please set chaining-mode in CNI configuration")
			return errors.New("CNI PrevResult supplied, but not in chaining mode -- this is invalid, please set chaining-mode in CNI configuration")
		}
	}

	res := &cniTypesV1.Result{}
	configs, err := cmd.cfg.GetConfigurations(ConfigurationParams{log, conf, args, cniArgs})
	if err != nil {
		return fmt.Errorf("failed to determine endpoint configuration: %w", err)
	}

	ns, err := netns.OpenPinned(args.Netns)
	if err != nil {
		return fmt.Errorf("opening netns pinned at %s: %w", args.Netns, err)
	}
	defer ns.Close()

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	for _, epConf := range configs {
		if err = ns.Do(func() error {
			return link.DeleteByName(epConf.IfName())
		}); err != nil {
			return fmt.Errorf("failed removing interface %q from namespace %q: %w",
				epConf.IfName(), args.Netns, err)
		}

		var ipam *models.IPAMResponse
		var releaseIPsFunc func(context.Context)
		if conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
			ipam, releaseIPsFunc, err = allocateIPsWithDelegatedPlugin(context.TODO(), conf, n, args.StdinData)
		} else {
			ipam, releaseIPsFunc, err = allocateIPsWithCiliumAgent(c, cniArgs, epConf.IPAMPool())
		}

		// release addresses on failure
		defer func() {
			if err != nil && releaseIPsFunc != nil {
				releaseIPsFunc(context.TODO())
			}
		}()

		if err != nil {
			return err
		}

		if err = connector.SufficientAddressing(ipam.HostAddressing); err != nil {
			return fmt.Errorf("IP allocation addressing is insufficient: %w", err)
		}

		if !ipv6IsEnabled(ipam) && !ipv4IsEnabled(ipam) {
			return errors.New("IPAM did provide neither IPv4 nor IPv6 address")
		}

		state, ep, err := epConf.PrepareEndpoint(ipam)
		if err != nil {
			return fmt.Errorf("unable to prepare endpoint configuration: %w", err)
		}

		switch conf.DatapathMode {
		case datapathOption.DatapathModeVeth:
			cniID := ep.ContainerID + ":" + ep.ContainerInterfaceName
			veth, peer, tmpIfName, err := connector.SetupVeth(cniID, int(conf.DeviceMTU),
				int(conf.GROMaxSize), int(conf.GSOMaxSize),
				int(conf.GROIPV4MaxSize), int(conf.GSOIPV4MaxSize), ep, sysctl)
			if err != nil {
				return fmt.Errorf("unable to set up veth on host side: %w", err)
			}
			defer func() {
				if err != nil {
					if err2 := netlink.LinkDel(veth); err2 != nil {
						logger.WithError(err2).WithField(logfields.Veth, veth.Name).Warn("failed to clean up and delete veth")
					}
				}
			}()

			res.Interfaces = append(res.Interfaces, &cniTypesV1.Interface{
				Name: veth.Attrs().Name,
				Mac:  veth.Attrs().HardwareAddr.String(),
			})

			if err := netlink.LinkSetNsFd(peer, ns.FD()); err != nil {
				return fmt.Errorf("unable to move veth pair %q to netns %s: %w", peer, args.Netns, err)
			}

			err = connector.SetupVethRemoteNs(ns, tmpIfName, epConf.IfName())
			if err != nil {
				return fmt.Errorf("unable to set up veth on container side: %w", err)
			}
		case datapathOption.DatapathModeNetkit, datapathOption.DatapathModeNetkitL2:
			l2Mode := conf.DatapathMode == datapathOption.DatapathModeNetkitL2
			cniID := ep.ContainerID + ":" + ep.ContainerInterfaceName
			netkit, peer, tmpIfName, err := connector.SetupNetkit(cniID, int(conf.DeviceMTU),
				int(conf.GROMaxSize), int(conf.GSOMaxSize),
				int(conf.GROIPV4MaxSize), int(conf.GSOIPV4MaxSize), l2Mode, ep, sysctl)
			if err != nil {
				return fmt.Errorf("unable to set up netkit on host side: %w", err)
			}
			defer func() {
				if err != nil {
					if err2 := netlink.LinkDel(netkit); err2 != nil {
						logger.WithError(err2).WithField(logfields.Netkit, netkit.Name).Warn("failed to clean up and delete netkit")
					}
				}
			}()

			iface := &cniTypesV1.Interface{
				Name: netkit.Attrs().Name,
			}
			if l2Mode {
				iface.Mac = netkit.Attrs().HardwareAddr.String()
			}
			res.Interfaces = append(res.Interfaces, iface)

			if err := netlink.LinkSetNsFd(peer, ns.FD()); err != nil {
				return fmt.Errorf("unable to move netkit pair %q to netns %s: %w", peer, args.Netns, err)
			}

			err = connector.SetupNetkitRemoteNs(ns, tmpIfName, epConf.IfName())
			if err != nil {
				return fmt.Errorf("unable to set up netkit on container side: %w", err)
			}
		}

		var (
			ipConfig *cniTypesV1.IPConfig
			routes   []*cniTypes.Route
		)
		if ipv6IsEnabled(ipam) && conf.Addressing.IPV6 != nil {
			ep.Addressing.IPV6 = ipam.Address.IPV6
			ep.Addressing.IPV6PoolName = ipam.Address.IPV6PoolName
			ep.Addressing.IPV6ExpirationUUID = ipam.IPV6.ExpirationUUID

			ipConfig, routes, err = prepareIP(ep.Addressing.IPV6, state, int(conf.RouteMTU))
			if err != nil {
				return fmt.Errorf("unable to prepare IP addressing for %s: %w", ep.Addressing.IPV6, err)
			}
			// set the addresses interface index to that of the container-side interface
			ipConfig.Interface = cniTypesV1.Int(len(res.Interfaces))
			res.IPs = append(res.IPs, ipConfig)
			res.Routes = append(res.Routes, routes...)
		}

		if ipv4IsEnabled(ipam) && conf.Addressing.IPV4 != nil {
			ep.Addressing.IPV4 = ipam.Address.IPV4
			ep.Addressing.IPV4PoolName = ipam.Address.IPV4PoolName
			ep.Addressing.IPV4ExpirationUUID = ipam.IPV4.ExpirationUUID

			ipConfig, routes, err = prepareIP(ep.Addressing.IPV4, state, int(conf.RouteMTU))
			if err != nil {
				return fmt.Errorf("unable to prepare IP addressing for %s: %w", ep.Addressing.IPV4, err)
			}
			// set the addresses interface index to that of the container-side interface
			ipConfig.Interface = cniTypesV1.Int(len(res.Interfaces))
			res.IPs = append(res.IPs, ipConfig)
			res.Routes = append(res.Routes, routes...)
		}

		switch conf.IpamMode {
		case ipamOption.IPAMENI, ipamOption.IPAMAzure, ipamOption.IPAMAlibabaCloud:
			err = interfaceAdd(ipConfig, ipam.IPV4, conf)
			if err != nil {
				return fmt.Errorf("unable to setup interface datapath: %w", err)
			}
		}

		var macAddrStr string

		if err = ns.Do(func() error {
			if err := reserveLocalIPPorts(conf, sysctl); err != nil {
				logger.WithError(err).Warn("unable to reserve local ip ports")
			}

			if ipv6IsEnabled(ipam) {
				if err := sysctl.Disable([]string{"net", "ipv6", "conf", "all", "disable_ipv6"}); err != nil {
					logger.WithError(err).Warn("unable to enable ipv6 on all interfaces")
				}
			}
			macAddrStr, err = configureIface(ipam, epConf.IfName(), state)
			return err
		}); err != nil {
			return fmt.Errorf("unable to configure interfaces in container namespace: %w", err)
		}

		var cookie uint64
		if getNetnsCookie {
			if err = ns.Do(func() error {
				cookie, err = netns.GetNetNSCookie()
				return err
			}); err != nil {
				if errors.Is(err, unix.ENOPROTOOPT) {
					getNetnsCookie = false
				}
				logger.WithError(err).WithFields(logrus.Fields{
					logfields.ContainerID: args.ContainerID}).Info("unable to get netns cookie")
			}
		}
		ep.NetnsCookie = strconv.FormatUint(cookie, 10)

		// Specify that endpoint must be regenerated synchronously. See GH-4409.
		ep.SyncBuildEndpoint = true
		var newEp *models.Endpoint
		if newEp, err = c.EndpointCreate(ep); err != nil {
			logger.WithError(err).WithField(logfields.ContainerID, ep.ContainerID).Warn("Unable to create endpoint")
			return fmt.Errorf("unable to create endpoint: %w", err)
		}
		if newEp != nil && newEp.Status != nil && newEp.Status.Networking != nil && newEp.Status.Networking.Mac != "" {
			// Set the MAC address on the interface in the container namespace
			if conf.DatapathMode != datapathOption.DatapathModeNetkit {
				err = ns.Do(func() error {
					return mac.ReplaceMacAddressWithLinkName(args.IfName, newEp.Status.Networking.Mac)
				})
				if err != nil {
					return fmt.Errorf("unable to set MAC address on interface %s: %w", args.IfName, err)
				}
			}
			macAddrStr = newEp.Status.Networking.Mac
		}
		res.Interfaces = append(res.Interfaces, &cniTypesV1.Interface{
			Name:    epConf.IfName(),
			Mac:     macAddrStr,
			Sandbox: args.Netns,
		})
		logger.WithError(err).WithField(logfields.ContainerID, ep.ContainerID).Debug("Endpoint successfully created")
	}

	return cniTypes.PrintResult(res, n.CNIVersion)
}

// Del is invoked on CNI DEL
//
// Note: ENI specific attributes do not need to be released as the ENIs and ENI
// IPs can be reused and are not released until the node terminates.
func (cmd *Cmd) Del(args *skel.CmdArgs) error {
	// Note about when to return errors: kubelet will retry the deletion
	// for a long time. Therefore, only return an error for errors which
	// are guaranteed to be recoverable.
	n, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("unable to parse CNI configuration %q: %w", string(args.StdinData), err)
	}

	if err := setupLogging(n); err != nil {
		return fmt.Errorf("unable to setup logging: %w", err)
	}

	logger := loggerWithArguments(log.WithField(logfields.EventUUID, uuid.New()), args)

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			log.WithError(err).Warn("Unable to start gops")
		} else {
			defer gops.Close()
		}
	}
	logger.WithField("netconf", logfields.Repr(n)).Debugf("Processing CNI DEL request")

	cniArgs := &types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, cniArgs); err != nil {
		return fmt.Errorf("unable to extract CNI arguments: %w", err)
	}
	logger = loggerWithCNIArgs(logger, cniArgs)

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

	req := &models.EndpointBatchDeleteRequest{ContainerID: args.ContainerID}
	if err := c.EndpointDeleteMany(req); err != nil {
		// EndpointDeleteMany returns an error in the following scenarios:
		// DeleteEndpointInvalid: Invalid delete parameters, no need to retry
		// DeleteEndpointNotFound: No need to retry
		// DeleteEndpointErrors: Errors encountered while deleting,
		//                       the endpoint is always deleted though, no
		//                       need to retry
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

	ns, err := netns.OpenPinned(args.Netns)
	if err != nil {
		return fmt.Errorf("opening netns pinned at %s: %w", args.Netns, err)
	}
	defer ns.Close()
	if err = ns.Do(func() error {
		return link.DeleteByName(args.IfName)
	}); err != nil {
		log.WithError(err).Warningf("Unable to delete interface %s in namespace %q, will not delete interface", args.IfName, args.Netns)
		// We are not returning an error as this is very unlikely to be recoverable
	}

	return nil
}

// Check implements the cni CHECK verb.
// It ensures that the interface is configured correctly
//
// Currently, it verifies that
// - endpoint exists in the agent and is healthy
// - the interface in the container is sane
func (cmd *Cmd) Check(args *skel.CmdArgs) error {
	n, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidNetworkConfig",
			fmt.Sprintf("unable to parse CNI configuration \"%s\": %v", string(args.StdinData), err))
	}

	if err := setupLogging(n); err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidLoggingConfig",
			fmt.Sprintf("unable to setup logging: %s", err))
	}

	logger := loggerWithArguments(log.WithField(logfields.EventUUID, uuid.New()), args)

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			log.WithError(err).Warn("Unable to start gops")
		} else {
			defer gops.Close()
		}
	}
	logger.WithField("netconf", logfields.Repr(n)).Debugf("Processing CNI CHECK request")

	if n.PrevResult != nil {
		logger.WithField("previousResult", logfields.Repr(n.PrevResult)).Debugf("CNI Previous result")
	}

	cniArgs := &types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, cniArgs); err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidArgs",
			fmt.Sprintf("unable to extract CNI arguments: %s", err))
	}
	logger = loggerWithCNIArgs(logger, cniArgs)

	c, err := client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		// use ErrTryAgainLater to tell the runtime that this is not a check failure
		return cniTypes.NewError(cniTypes.ErrTryAgainLater, "DaemonDown",
			fmt.Sprintf("unable to connect to Cilium agent: %s", client.Hint(err)))
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
		logger.WithError(err).Debugf("Chained CHECK %s returned", n.Name)
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

	// Ask the agent for the endpoint's health
	eID := endpointid.NewCNIAttachmentID(args.ContainerID, args.IfName)
	logger.WithField(logfields.EndpointID, eID).Debugf("Asking agent for healthz")
	epHealth, err := c.EndpointHealthGet(eID)
	if err != nil {
		return cniTypes.NewError(types.CniErrHealthzGet, "HealthzFailed",
			fmt.Sprintf("failed to retrieve container health: %s", err))
	}

	if epHealth.OverallHealth == models.EndpointHealthStatusFailure {
		return cniTypes.NewError(types.CniErrUnhealthy, "Unhealthy",
			"container is unhealthy in agent")
	}
	logger.Debugf("Container %s:%s has a healthy agent endpoint", args.ContainerID, args.IfName)

	// Verify that the interface exists and has the desired IP address
	// we can get the IP from the CNI previous result.
	if err := verifyInterface(args.Netns, args.IfName, prevResult); err != nil {
		return err
	}

	return nil
}

// verifyInterface verifies that a given interface exists in the netns
// with the given addresses
func verifyInterface(netnsPinPath, ifName string, expected *cniTypesV1.Result) error {
	var wantAddresses []*cniTypesV1.IPConfig
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
	ns, err := netns.OpenPinned(netnsPinPath)
	if err != nil {
		return fmt.Errorf("opening netns pinned at %s: %w", netnsPinPath, err)
	}
	defer ns.Close()
	return ns.Do(func() error {
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

func loggerWithArguments(logger *logrus.Entry, args *skel.CmdArgs) *logrus.Entry {
	return logger.WithFields(logrus.Fields{
		logfields.ContainerID: args.ContainerID,
		"netns":               args.Netns,
		"ifName":              args.IfName,
		"args":                args.Args,
		logfields.Path:        args.Path,
	})
}

func loggerWithCNIArgs(logger *logrus.Entry, cniArgs *types.ArgsSpec) *logrus.Entry {
	return logger.WithFields(logrus.Fields{
		logfields.K8sNamespace: cniArgs.K8S_POD_NAMESPACE,
		logfields.K8sPodName:   cniArgs.K8S_POD_NAME,
	})
}
