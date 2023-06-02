// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"
	versionapi "k8s.io/apimachinery/pkg/version"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	ipmasqmap "github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	tunnelmap "github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/version"
)

const (
	// k8sVersionCheckInterval is the interval in which the Kubernetes
	// version is verified even if connectivity is given
	k8sVersionCheckInterval = 15 * time.Minute

	// k8sMinimumEventHearbeat is the time interval in which any received
	// event will be considered proof that the apiserver connectivity is
	// healthty
	k8sMinimumEventHearbeat = time.Minute
)

var randGen = rand.NewSafeRand(time.Now().UnixNano())

type k8sVersion struct {
	version          string
	lastVersionCheck time.Time
	lock             lock.Mutex
}

func (k *k8sVersion) cachedVersion() (string, bool) {
	k.lock.Lock()
	defer k.lock.Unlock()

	if time.Since(k8smetrics.LastInteraction.Time()) > k8sMinimumEventHearbeat {
		return "", false
	}

	if k.version == "" || time.Since(k.lastVersionCheck) > k8sVersionCheckInterval {
		return "", false
	}

	return k.version, true
}

func (k *k8sVersion) update(version *versionapi.Info) string {
	k.lock.Lock()
	defer k.lock.Unlock()

	k.version = fmt.Sprintf("%s.%s (%s) [%s]", version.Major, version.Minor, version.GitVersion, version.Platform)
	k.lastVersionCheck = time.Now()
	return k.version
}

var k8sVersionCache k8sVersion

func (d *Daemon) getK8sStatus() *models.K8sStatus {
	if !d.clientset.IsEnabled() {
		return &models.K8sStatus{State: models.StatusStateDisabled}
	}

	version, valid := k8sVersionCache.cachedVersion()
	if !valid {
		k8sVersion, err := d.clientset.Discovery().ServerVersion()
		if err != nil {
			return &models.K8sStatus{State: models.StatusStateFailure, Msg: err.Error()}
		}

		version = k8sVersionCache.update(k8sVersion)
	}

	k8sStatus := &models.K8sStatus{
		State:          models.StatusStateOk,
		Msg:            version,
		K8sAPIVersions: d.k8sWatcher.GetAPIGroups(),
	}

	return k8sStatus
}

func (d *Daemon) getMasqueradingStatus() *models.Masquerading {
	s := &models.Masquerading{
		Enabled: option.Config.MasqueradingEnabled(),
		EnabledProtocols: &models.MasqueradingEnabledProtocols{
			IPV4: option.Config.EnableIPv4Masquerade,
			IPV6: option.Config.EnableIPv6Masquerade,
		},
	}

	if !option.Config.MasqueradingEnabled() {
		return s
	}

	if option.Config.EnableIPv4 {
		// SnatExclusionCidr is the legacy field, continue to provide
		// it for the time being
		s.SnatExclusionCidr = datapath.RemoteSNATDstAddrExclusionCIDRv4().String()
		s.SnatExclusionCidrV4 = datapath.RemoteSNATDstAddrExclusionCIDRv4().String()
	}

	if option.Config.EnableIPv6 {
		s.SnatExclusionCidrV6 = datapath.RemoteSNATDstAddrExclusionCIDRv6().String()
	}

	if option.Config.EnableBPFMasquerade {
		s.Mode = models.MasqueradingModeBPF
		s.IPMasqAgent = option.Config.EnableIPMasqAgent
		return s
	}

	s.Mode = models.MasqueradingModeIptables
	return s
}

func (d *Daemon) getIPV6BigTCPStatus() *models.IPV6BigTCP {
	s := &models.IPV6BigTCP{
		Enabled: option.Config.EnableIPv6BIGTCP,
	}

	return s
}

func (d *Daemon) getBandwidthManagerStatus() *models.BandwidthManager {
	s := &models.BandwidthManager{
		Enabled: option.Config.EnableBandwidthManager,
	}

	if !option.Config.EnableBandwidthManager {
		return s
	}

	s.CongestionControl = models.BandwidthManagerCongestionControlCubic
	if option.Config.EnableBBR {
		s.CongestionControl = models.BandwidthManagerCongestionControlBbr
	}

	s.Devices = option.Config.GetDevices()
	return s
}

func (d *Daemon) getHostRoutingStatus() *models.HostRouting {
	s := &models.HostRouting{Mode: models.HostRoutingModeBPF}
	if option.Config.EnableHostLegacyRouting {
		s.Mode = models.HostRoutingModeLegacy
	}
	return s
}

func (d *Daemon) getHostFirewallStatus() *models.HostFirewall {
	mode := models.HostFirewallModeDisabled
	if option.Config.EnableHostFirewall {
		mode = models.HostFirewallModeEnabled
	}
	return &models.HostFirewall{
		Mode:    mode,
		Devices: option.Config.GetDevices(),
	}
}

func (d *Daemon) getClockSourceStatus() *models.ClockSource {
	s := &models.ClockSource{Mode: models.ClockSourceModeKtime}
	if option.Config.ClockSource == option.ClockSourceJiffies {
		s.Mode = models.ClockSourceModeJiffies
		s.Hertz = int64(option.Config.KernelHz)
	}
	return s
}

func (d *Daemon) getCNIChainingStatus() *models.CNIChainingStatus {
	mode := d.cniConfigManager.GetChainingMode()
	if len(mode) == 0 {
		mode = models.CNIChainingStatusModeNone
	}
	return &models.CNIChainingStatus{
		Mode: mode,
	}
}

func (d *Daemon) getKubeProxyReplacementStatus() *models.KubeProxyReplacement {
	var mode string
	switch option.Config.KubeProxyReplacement {
	case option.KubeProxyReplacementStrict:
		mode = models.KubeProxyReplacementModeStrict
	case option.KubeProxyReplacementPartial:
		mode = models.KubeProxyReplacementModePartial
	case option.KubeProxyReplacementDisabled:
		mode = models.KubeProxyReplacementModeDisabled
	}

	devicesLegacy := option.Config.GetDevices()
	devices := make([]*models.KubeProxyReplacementDeviceListItems0, len(devicesLegacy))
	v4Addrs := node.GetNodePortIPv4AddrsWithDevices()
	v6Addrs := node.GetNodePortIPv6AddrsWithDevices()
	for i, iface := range devicesLegacy {
		info := &models.KubeProxyReplacementDeviceListItems0{
			Name: iface,
			IP:   make([]string, 0),
		}
		if addr, ok := v4Addrs[iface]; ok {
			info.IP = append(info.IP, addr.String())
		}
		if addr, ok := v6Addrs[iface]; ok {
			info.IP = append(info.IP, addr.String())
		}
		devices[i] = info
	}

	features := &models.KubeProxyReplacementFeatures{
		NodePort:              &models.KubeProxyReplacementFeaturesNodePort{},
		HostPort:              &models.KubeProxyReplacementFeaturesHostPort{},
		ExternalIPs:           &models.KubeProxyReplacementFeaturesExternalIPs{},
		SocketLB:              &models.KubeProxyReplacementFeaturesSocketLB{},
		SocketLBTracing:       &models.KubeProxyReplacementFeaturesSocketLBTracing{},
		SessionAffinity:       &models.KubeProxyReplacementFeaturesSessionAffinity{},
		GracefulTermination:   &models.KubeProxyReplacementFeaturesGracefulTermination{},
		Nat46X64:              &models.KubeProxyReplacementFeaturesNat46X64{},
		BpfSocketLBHostnsOnly: option.Config.BPFSocketLBHostnsOnly,
	}
	if option.Config.EnableNodePort {
		features.NodePort.Enabled = true
		features.NodePort.Mode = strings.ToUpper(option.Config.NodePortMode)
		if option.Config.NodePortMode == option.NodePortModeHybrid {
			features.NodePort.Mode = strings.Title(option.Config.NodePortMode)
		}
		features.NodePort.Algorithm = models.KubeProxyReplacementFeaturesNodePortAlgorithmRandom
		if option.Config.NodePortAlg == option.NodePortAlgMaglev {
			features.NodePort.Algorithm = models.KubeProxyReplacementFeaturesNodePortAlgorithmMaglev
			features.NodePort.LutSize = int64(option.Config.MaglevTableSize)
		}
		if option.Config.NodePortAcceleration == option.NodePortAccelerationGeneric {
			features.NodePort.Acceleration = models.KubeProxyReplacementFeaturesNodePortAccelerationGeneric
		} else {
			features.NodePort.Acceleration = strings.Title(option.Config.NodePortAcceleration)
		}
		features.NodePort.PortMin = int64(option.Config.NodePortMin)
		features.NodePort.PortMax = int64(option.Config.NodePortMax)
	}
	if option.Config.EnableHostPort {
		features.HostPort.Enabled = true
	}
	if option.Config.EnableExternalIPs {
		features.ExternalIPs.Enabled = true
	}
	if option.Config.EnableSocketLB {
		features.SocketLB.Enabled = true
		features.SocketLBTracing.Enabled = true
	}
	if option.Config.EnableSessionAffinity {
		features.SessionAffinity.Enabled = true
	}
	if option.Config.EnableK8sTerminatingEndpoint {
		features.GracefulTermination.Enabled = true
	}
	if option.Config.NodePortNat46X64 || option.Config.EnableNat46X64Gateway {
		features.Nat46X64.Enabled = true
		gw := &models.KubeProxyReplacementFeaturesNat46X64Gateway{
			Enabled:  option.Config.EnableNat46X64Gateway,
			Prefixes: make([]string, 0),
		}
		if option.Config.EnableNat46X64Gateway {
			gw.Prefixes = append(gw.Prefixes, option.Config.IPv6NAT46x64CIDR)
		}
		features.Nat46X64.Gateway = gw

		svc := &models.KubeProxyReplacementFeaturesNat46X64Service{
			Enabled: option.Config.NodePortNat46X64,
		}
		features.Nat46X64.Service = svc
	}

	return &models.KubeProxyReplacement{
		Mode:                mode,
		Devices:             devicesLegacy,
		DeviceList:          devices,
		DirectRoutingDevice: option.Config.DirectRoutingDevice,
		Features:            features,
	}
}

func (d *Daemon) getBPFMapStatus() *models.BPFMapStatus {
	return &models.BPFMapStatus{
		DynamicSizeRatio: option.Config.BPFMapsDynamicSizeRatio,
		Maps: []*models.BPFMapProperties{
			{
				Name: "Auth",
				Size: int64(option.Config.AuthMapEntries),
			},
			{
				Name: "Non-TCP connection tracking",
				Size: int64(option.Config.CTMapEntriesGlobalAny),
			},
			{
				Name: "TCP connection tracking",
				Size: int64(option.Config.CTMapEntriesGlobalTCP),
			},
			{
				Name: "Endpoint policy",
				Size: int64(lxcmap.MaxEntries),
			},
			{
				Name: "IP cache",
				Size: int64(ipcachemap.MaxEntries),
			},
			{
				Name: "IP masquerading agent",
				Size: int64(ipmasqmap.MaxEntries),
			},
			{
				Name: "IPv4 fragmentation",
				Size: int64(option.Config.FragmentsMapEntries),
			},
			{
				Name: "IPv4 service", // cilium_lb4_services_v2
				Size: int64(lbmap.ServiceMapMaxEntries),
			},
			{
				Name: "IPv6 service", // cilium_lb6_services_v2
				Size: int64(lbmap.ServiceMapMaxEntries),
			},
			{
				Name: "IPv4 service backend", // cilium_lb4_backends_v2
				Size: int64(lbmap.ServiceBackEndMapMaxEntries),
			},
			{
				Name: "IPv6 service backend", // cilium_lb6_backends_v2
				Size: int64(lbmap.ServiceBackEndMapMaxEntries),
			},
			{
				Name: "IPv4 service reverse NAT", // cilium_lb4_reverse_nat
				Size: int64(lbmap.RevNatMapMaxEntries),
			},
			{
				Name: "IPv6 service reverse NAT", // cilium_lb6_reverse_nat
				Size: int64(lbmap.RevNatMapMaxEntries),
			},
			{
				Name: "Metrics",
				Size: int64(metricsmap.MaxEntries),
			},
			{
				Name: "NAT",
				Size: int64(option.Config.NATMapEntriesGlobal),
			},
			{
				Name: "Neighbor table",
				Size: int64(option.Config.NeighMapEntriesGlobal),
			},
			{
				Name: "Global policy",
				Size: int64(option.Config.PolicyMapEntries),
			},
			{
				Name: "Session affinity",
				Size: int64(lbmap.AffinityMapMaxEntries),
			},
			{
				Name: "Sock reverse NAT",
				Size: int64(option.Config.SockRevNatEntries),
			},
			{
				Name: "Tunnel",
				Size: int64(tunnelmap.MaxEntries),
			},
		},
	}
}

type getHealthz struct {
	daemon *Daemon
}

func NewGetHealthzHandler(d *Daemon) GetHealthzHandler {
	return &getHealthz{daemon: d}
}

func (d *Daemon) getNodeStatus() *models.ClusterStatus {
	clusterStatus := models.ClusterStatus{
		Self: nodeTypes.GetAbsoluteNodeName(),
	}
	for _, node := range d.nodeDiscovery.Manager.GetNodes() {
		clusterStatus.Nodes = append(clusterStatus.Nodes, node.GetModel())
	}
	return &clusterStatus
}

func (h *getHealthz) Handle(params GetHealthzParams) middleware.Responder {
	brief := params.Brief != nil && *params.Brief
	sr := h.daemon.getStatus(brief)

	return NewGetHealthzOK().WithPayload(&sr)
}

type getNodes struct {
	d *Daemon
	// mutex to protect the clients map against concurrent access
	lock.RWMutex
	// clients maps a client ID to a clusterNodesClient
	clients map[int64]*clusterNodesClient
}

func NewGetClusterNodesHandler(d *Daemon) GetClusterNodesHandler {
	return &getNodes{
		d:       d,
		clients: map[int64]*clusterNodesClient{},
	}
}

// clientGCTimeout is the time for which the clients are kept. After timeout
// is reached, clients will be cleaned up.
const clientGCTimeout = 15 * time.Minute

type clusterNodesClient struct {
	// mutex to protect the client against concurrent access
	lock.RWMutex
	lastSync time.Time
	*models.ClusterNodeStatus
}

func (c *clusterNodesClient) NodeAdd(newNode nodeTypes.Node) error {
	c.Lock()
	c.NodesAdded = append(c.NodesAdded, newNode.GetModel())
	c.Unlock()
	return nil
}

func (c *clusterNodesClient) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	c.Lock()
	defer c.Unlock()

	// If the node is on the added list, just update it
	for i, added := range c.NodesAdded {
		if added.Name == newNode.Fullname() {
			c.NodesAdded[i] = newNode.GetModel()
			return nil
		}
	}

	// otherwise, add the new node and remove the old one
	c.NodesAdded = append(c.NodesAdded, newNode.GetModel())
	c.NodesRemoved = append(c.NodesRemoved, oldNode.GetModel())
	return nil
}

func (c *clusterNodesClient) NodeDelete(node nodeTypes.Node) error {
	c.Lock()
	// If the node was added/updated and removed before the clusterNodesClient
	// was aware of it then we can safely remove it from the list of added
	// nodes and not set it in the list of removed nodes.
	found := -1
	for i, added := range c.NodesAdded {
		if added.Name == node.Fullname() {
			found = i
		}
	}
	if found != -1 {
		c.NodesAdded = append(c.NodesAdded[:found], c.NodesAdded[found+1:]...)
	} else {
		c.NodesRemoved = append(c.NodesRemoved, node.GetModel())
	}
	c.Unlock()
	return nil
}

func (c *clusterNodesClient) NodeValidateImplementation(node nodeTypes.Node) error {
	// no-op
	return nil
}

func (c *clusterNodesClient) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	// no-op
	return nil
}

func (h *getNodes) cleanupClients() {
	past := time.Now().Add(-clientGCTimeout)
	for k, v := range h.clients {
		if v.lastSync.Before(past) {
			h.d.nodeDiscovery.Manager.Unsubscribe(v)
			delete(h.clients, k)
		}
	}
}

func (h *getNodes) Handle(params GetClusterNodesParams) middleware.Responder {
	var cns *models.ClusterNodeStatus
	// If ClientID is not set then we send all nodes, otherwise we will store
	// the client ID in the list of clients and we subscribe this new client
	// to the list of clients.
	if params.ClientID == nil {
		ns := h.d.getNodeStatus()
		cns = &models.ClusterNodeStatus{
			Self:       ns.Self,
			NodesAdded: ns.Nodes,
		}
		return NewGetClusterNodesOK().WithPayload(cns)
	}

	h.Lock()
	defer h.Unlock()

	var clientID int64
	c, exists := h.clients[*params.ClientID]
	if exists {
		clientID = *params.ClientID
	} else {
		clientID = randGen.Int63()
		// make sure we haven't allocated an existing client ID nor the
		// randomizer has allocated ID 0, if we have then we will return
		// clientID 0.
		_, exists := h.clients[clientID]
		if exists || clientID == 0 {
			ns := h.d.getNodeStatus()
			cns = &models.ClusterNodeStatus{
				ClientID:   0,
				Self:       ns.Self,
				NodesAdded: ns.Nodes,
			}
			return NewGetClusterNodesOK().WithPayload(cns)
		}
		c = &clusterNodesClient{
			lastSync: time.Now(),
			ClusterNodeStatus: &models.ClusterNodeStatus{
				ClientID: clientID,
				Self:     nodeTypes.GetAbsoluteNodeName(),
			},
		}
		h.d.nodeDiscovery.Manager.Subscribe(c)

		// Clean up other clients before adding a new one
		h.cleanupClients()
		h.clients[clientID] = c
	}
	c.Lock()
	// Copy the ClusterNodeStatus to the response
	cns = c.ClusterNodeStatus
	// Store a new ClusterNodeStatus to reset the list of nodes
	// added / removed.
	c.ClusterNodeStatus = &models.ClusterNodeStatus{
		ClientID: clientID,
		Self:     nodeTypes.GetAbsoluteNodeName(),
	}
	c.lastSync = time.Now()
	c.Unlock()

	return NewGetClusterNodesOK().WithPayload(cns)
}

// getStatus returns the daemon status. If brief is provided a minimal version
// of the StatusResponse is provided.
func (d *Daemon) getStatus(brief bool) models.StatusResponse {
	staleProbes := d.statusCollector.GetStaleProbes()
	stale := make(map[string]strfmt.DateTime, len(staleProbes))
	for probe, startTime := range staleProbes {
		stale[probe] = strfmt.DateTime(startTime)
	}

	d.statusCollectMutex.RLock()
	defer d.statusCollectMutex.RUnlock()

	var sr models.StatusResponse
	if brief {
		csCopy := new(models.ClusterStatus)
		if d.statusResponse.Cluster != nil && d.statusResponse.Cluster.CiliumHealth != nil {
			in, out := &d.statusResponse.Cluster.CiliumHealth, &csCopy.CiliumHealth
			*out = new(models.Status)
			**out = **in
		}
		var minimalControllers models.ControllerStatuses
		if d.statusResponse.Controllers != nil {
			for _, c := range d.statusResponse.Controllers {
				if c.Status == nil {
					continue
				}
				// With brief, the client should only care if a single controller
				// is failing and its status so we don't need to continuing
				// checking for failure messages for the remaining controllers.
				if c.Status.LastFailureMsg != "" {
					minimalControllers = append(minimalControllers, c.DeepCopy())
					break
				}
			}
		}
		sr = models.StatusResponse{
			Cluster:     csCopy,
			Controllers: minimalControllers,
		}
	} else {
		// d.statusResponse contains references, so we do a deep copy to be able to
		// safely use sr after the method has returned
		sr = *d.statusResponse.DeepCopy()
	}

	sr.Stale = stale

	// CiliumVersion definition
	ver := version.GetCiliumVersion()
	ciliumVer := fmt.Sprintf("%s (v%s-%s)", ver.Version, ver.Version, ver.Revision)

	switch {
	case len(sr.Stale) > 0:
		msg := "Stale status data"
		sr.Cilium = &models.Status{
			State: models.StatusStateWarning,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.Kvstore != nil && d.statusResponse.Kvstore.State != models.StatusStateOk:
		msg := "Kvstore service is not ready"
		sr.Cilium = &models.Status{
			State: d.statusResponse.Kvstore.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.ContainerRuntime != nil && d.statusResponse.ContainerRuntime.State != models.StatusStateOk:
		msg := "Container runtime is not ready"
		if d.statusResponse.ContainerRuntime.State == models.StatusStateDisabled {
			msg = "Container runtime is disabled"
		}
		sr.Cilium = &models.Status{
			State: d.statusResponse.ContainerRuntime.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.clientset.IsEnabled() && d.statusResponse.Kubernetes != nil && d.statusResponse.Kubernetes.State != models.StatusStateOk:
		msg := "Kubernetes service is not ready"
		sr.Cilium = &models.Status{
			State: d.statusResponse.Kubernetes.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.CniFile != nil && d.statusResponse.CniFile.State == models.StatusStateFailure:
		msg := "Could not write CNI config file"
		sr.Cilium = &models.Status{
			State: models.StatusStateFailure,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	default:
		sr.Cilium = &models.Status{
			State: models.StatusStateOk,
			Msg:   ciliumVer,
		}
	}

	return sr
}

func (d *Daemon) getIdentityRange() *models.IdentityRange {
	s := &models.IdentityRange{
		MinIdentity: int64(identity.MinimalAllocationIdentity),
		MaxIdentity: int64(identity.MaximumAllocationIdentity),
	}

	return s
}

func (d *Daemon) startStatusCollector(cleaner *daemonCleanup) {
	probes := []status.Probe{
		{
			Name: "check-locks",
			Probe: func(ctx context.Context) (interface{}, error) {
				// Try to acquire a couple of global locks to have the status API fail
				// in case of a deadlock on these locks
				option.Config.ConfigPatchMutex.Lock()
				option.Config.ConfigPatchMutex.Unlock()
				return nil, nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()
				// FIXME we have no field for the lock status
			},
		},
		{
			Name: "kvstore",
			Probe: func(ctx context.Context) (interface{}, error) {
				if option.Config.KVStore == "" {
					return models.StatusStateDisabled, nil
				} else {
					return kvstore.Client().Status()
				}
			},
			OnStatusUpdate: func(status status.Status) {
				var msg string
				state := models.StatusStateOk
				info, ok := status.Data.(string)

				switch {
				case ok && status.Err != nil:
					state = models.StatusStateFailure
					msg = fmt.Sprintf("Err: %s - %s", status.Err, info)
				case status.Err != nil:
					state = models.StatusStateFailure
					msg = fmt.Sprintf("Err: %s", status.Err)
				case ok:
					msg = fmt.Sprintf("%s", info)
				}

				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				d.statusResponse.Kvstore = &models.Status{
					State: state,
					Msg:   msg,
				}
			},
		},
		{
			Name: "kubernetes",
			Interval: func(failures int) time.Duration {
				if failures > 0 {
					// While failing, we want an initial
					// quick retry with exponential backoff
					// to avoid continuous load on the
					// apiserver
					return backoff.CalculateDuration(5*time.Second, 2*time.Minute, 2.0, false, failures)
				}

				// The base interval is dependant on the
				// cluster size. One status interval does not
				// automatically translate to an apiserver
				// interaction as any regular apiserver
				// interaction is also used as an indication of
				// successful connectivity so we can continue
				// to be fairly aggressive.
				//
				// 1     |    7s
				// 2     |   12s
				// 4     |   15s
				// 64    |   42s
				// 512   | 1m02s
				// 2048  | 1m15s
				// 8192  | 1m30s
				// 16384 | 1m32s
				return d.nodeDiscovery.Manager.ClusterSizeDependantInterval(10 * time.Second)
			},
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.getK8sStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err != nil {
					d.statusResponse.Kubernetes = &models.K8sStatus{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}
				if s, ok := status.Data.(*models.K8sStatus); ok {
					d.statusResponse.Kubernetes = s
				}
			},
		},
		{
			Name: "ipam",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.DumpIPAM(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// IPAMStatus has no way to show errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.IPAMStatus); ok {
						d.statusResponse.Ipam = s
					}
				}
			},
		},
		{
			Name: "node-monitor",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.monitorAgent.State(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// NodeMonitor has no way to show errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.MonitorStatus); ok {
						d.statusResponse.NodeMonitor = s
					}
				}
			},
		},
		{
			Name: "cluster",
			Probe: func(ctx context.Context) (interface{}, error) {
				clusterStatus := &models.ClusterStatus{
					Self: nodeTypes.GetAbsoluteNodeName(),
				}
				return clusterStatus, nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ClusterStatus has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.ClusterStatus); ok {
						if d.statusResponse.Cluster != nil {
							// NB: CiliumHealth is set concurrently by the
							// "cilium-health" probe, so do not override it
							s.CiliumHealth = d.statusResponse.Cluster.CiliumHealth
						}
						d.statusResponse.Cluster = s
					}
				}
			},
		},
		{
			Name: "cilium-health",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.ciliumHealth == nil {
					return nil, nil
				}
				return d.ciliumHealth.GetStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				if d.ciliumHealth == nil {
					return
				}

				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if d.statusResponse.Cluster == nil {
					d.statusResponse.Cluster = &models.ClusterStatus{}
				}
				if status.Err != nil {
					d.statusResponse.Cluster.CiliumHealth = &models.Status{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}
				if s, ok := status.Data.(*models.Status); ok {
					d.statusResponse.Cluster.CiliumHealth = s
				}
			},
		},
		{
			Name: "l7-proxy",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.l7Proxy == nil {
					return nil, nil
				}
				return d.l7Proxy.GetStatusModel(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ProxyStatus has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.ProxyStatus); ok {
						d.statusResponse.Proxy = s
					}
				}
			},
		},
		{
			Name: "controllers",
			Probe: func(ctx context.Context) (interface{}, error) {
				return controller.GetGlobalStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ControllerStatuses has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(models.ControllerStatuses); ok {
						d.statusResponse.Controllers = s
					}
				}
			},
		},
		{
			Name: "clustermesh",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.clustermesh == nil {
					return nil, nil
				}
				return d.clustermesh.Status(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.ClusterMeshStatus); ok {
						d.statusResponse.ClusterMesh = s
					}
				}
			},
		},
		{
			Name: "hubble",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.getHubbleStatus(ctx), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.HubbleStatus); ok {
						d.statusResponse.Hubble = s
					}
				}
			},
		},
		{
			Name: "encryption",
			Probe: func(ctx context.Context) (interface{}, error) {
				switch {
				case option.Config.EnableIPSec:
					return &models.EncryptionStatus{
						Mode: models.EncryptionStatusModeIPsec,
					}, nil
				case option.Config.EnableWireguard:
					var msg string
					status, err := d.datapath.WireguardAgent().Status(false)
					if err != nil {
						msg = err.Error()
					}
					return &models.EncryptionStatus{
						Mode:      models.EncryptionStatusModeWireguard,
						Msg:       msg,
						Wireguard: status,
					}, nil
				default:
					return &models.EncryptionStatus{
						Mode: models.EncryptionStatusModeDisabled,
					}, nil
				}
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.EncryptionStatus); ok {
						d.statusResponse.Encryption = s
					}
				}
			},
		},
		{
			Name: "kube-proxy-replacement",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.clientset.IsEnabled() || option.Config.DatapathMode == datapathOption.DatapathModeLBOnly {
					return d.getKubeProxyReplacementStatus(), nil
				} else {
					return nil, nil
				}
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.KubeProxyReplacement); ok {
						d.statusResponse.KubeProxyReplacement = s
					}
				}
			},
		},
	}

	d.statusResponse.Masquerading = d.getMasqueradingStatus()
	d.statusResponse.IPV6BigTCP = d.getIPV6BigTCPStatus()
	d.statusResponse.BandwidthManager = d.getBandwidthManagerStatus()
	d.statusResponse.HostFirewall = d.getHostFirewallStatus()
	d.statusResponse.HostRouting = d.getHostRoutingStatus()
	d.statusResponse.ClockSource = d.getClockSourceStatus()
	d.statusResponse.BpfMaps = d.getBPFMapStatus()
	d.statusResponse.CniChaining = d.getCNIChainingStatus()
	d.statusResponse.IdentityRange = d.getIdentityRange()

	d.statusCollector = status.NewCollector(probes, status.Config{StackdumpPath: "/run/cilium/state/agent.stack.gz"})

	// Set up a signal handler function which prints out logs related to daemon status.
	cleaner.cleanupFuncs.Add(func() {
		// If the KVstore state is not OK, print help for user.
		if d.statusResponse.Kvstore != nil &&
			d.statusResponse.Kvstore.State != models.StatusStateOk {
			helpMsg := "cilium-agent depends on the availability of cilium-operator/etcd-cluster. " +
				"Check if the cilium-operator pod and etcd-cluster are running and do not have any " +
				"warnings or error messages."
			log.WithFields(logrus.Fields{
				"status":              d.statusResponse.Kvstore.Msg,
				logfields.HelpMessage: helpMsg,
			}).Error("KVStore state not OK")

		}
	})
	return
}
