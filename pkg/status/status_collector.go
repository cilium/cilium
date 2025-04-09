// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-openapi/strfmt"
	versionapi "k8s.io/apimachinery/pkg/version"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	ipmasqmap "github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/ratelimitmap"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

type StatusCollector interface {
	GetStatus(brief bool, requireK8sConnectivity bool) models.StatusResponse
}

type statusCollector struct {
	statusCollectMutex lock.RWMutex
	statusResponse     models.StatusResponse
	statusCollector    *Collector

	allProbesInitialized bool

	statusParams statusParams
}

var _ StatusCollector = &statusCollector{}

const (
	// k8sVersionCheckInterval is the interval in which the Kubernetes
	// version is verified even if connectivity is given
	k8sVersionCheckInterval = 15 * time.Minute

	// k8sMinimumEventHeartbeat is the time interval in which any received
	// event will be considered proof that the apiserver connectivity is
	// healthy
	k8sMinimumEventHeartbeat = time.Minute
)

type k8sVersion struct {
	version          string
	lastVersionCheck time.Time
	lock             lock.Mutex
}

func (k *k8sVersion) cachedVersion() (string, bool) {
	k.lock.Lock()
	defer k.lock.Unlock()

	if time.Since(k8smetrics.LastSuccessInteraction.Time()) > k8sMinimumEventHeartbeat {
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

func (d *statusCollector) getK8sStatus() *models.K8sStatus {
	if !d.statusParams.Clientset.IsEnabled() {
		return &models.K8sStatus{State: models.StatusStateDisabled}
	}

	version, valid := k8sVersionCache.cachedVersion()
	if !valid {
		k8sVersion, err := d.statusParams.Clientset.Discovery().ServerVersion()
		if err != nil {
			return &models.K8sStatus{State: models.StatusStateFailure, Msg: err.Error()}
		}

		version = k8sVersionCache.update(k8sVersion)
	}

	k8sStatus := &models.K8sStatus{
		State:          models.StatusStateOk,
		Msg:            version,
		K8sAPIVersions: d.statusParams.K8sWatcher.GetAPIGroups(),
	}

	return k8sStatus
}

func (d *statusCollector) getMasqueradingStatus(ctx context.Context) (*models.Masquerading, error) {
	s := &models.Masquerading{
		Enabled: d.statusParams.DaemonConfig.MasqueradingEnabled(),
		EnabledProtocols: &models.MasqueradingEnabledProtocols{
			IPV4: d.statusParams.DaemonConfig.EnableIPv4Masquerade,
			IPV6: d.statusParams.DaemonConfig.EnableIPv6Masquerade,
		},
	}

	if !d.statusParams.DaemonConfig.MasqueradingEnabled() {
		return s, nil
	}

	localNode, err := d.statusParams.NodeLocalStore.Get(ctx)
	if err != nil {
		return s, err
	}

	if d.statusParams.DaemonConfig.EnableIPv4 {
		// SnatExclusionCidr is the legacy field, continue to provide
		// it for the time being
		addr := datapath.RemoteSNATDstAddrExclusionCIDRv4(localNode)
		if addr == nil {
			return s, errors.New("no local node v4 CIDR")
		}

		s.SnatExclusionCidr = addr.String()
		s.SnatExclusionCidrV4 = addr.String()
	}

	if d.statusParams.DaemonConfig.EnableIPv6 {
		addr := datapath.RemoteSNATDstAddrExclusionCIDRv6(localNode)
		if addr == nil {
			return s, errors.New("no local node v6 CIDR")
		}
		s.SnatExclusionCidrV6 = addr.String()
	}

	if d.statusParams.DaemonConfig.EnableBPFMasquerade {
		s.Mode = models.MasqueradingModeBPF
		s.IPMasqAgent = d.statusParams.DaemonConfig.EnableIPMasqAgent
		return s, nil
	}

	s.Mode = models.MasqueradingModeIptables
	return s, nil
}

func (d *statusCollector) getSRv6Status() *models.Srv6 {
	return &models.Srv6{
		Enabled:       d.statusParams.DaemonConfig.EnableSRv6,
		Srv6EncapMode: d.statusParams.DaemonConfig.SRv6EncapMode,
	}
}

func (d *statusCollector) getIPV6BigTCPStatus() *models.IPV6BigTCP {
	s := &models.IPV6BigTCP{
		Enabled: d.statusParams.BigTCPConfig.EnableIPv6BIGTCP,
		MaxGRO:  int64(d.statusParams.BigTCPConfig.GetGROIPv6MaxSize()),
		MaxGSO:  int64(d.statusParams.BigTCPConfig.GetGSOIPv6MaxSize()),
	}

	return s
}

func (d *statusCollector) getIPV4BigTCPStatus() *models.IPV4BigTCP {
	s := &models.IPV4BigTCP{
		Enabled: d.statusParams.BigTCPConfig.EnableIPv4BIGTCP,
		MaxGRO:  int64(d.statusParams.BigTCPConfig.GetGROIPv4MaxSize()),
		MaxGSO:  int64(d.statusParams.BigTCPConfig.GetGSOIPv4MaxSize()),
	}

	return s
}

func (d *statusCollector) getBandwidthManagerStatus() *models.BandwidthManager {
	s := &models.BandwidthManager{
		Enabled: d.statusParams.BandwidthManager.Enabled(),
	}

	if !d.statusParams.BandwidthManager.Enabled() {
		return s
	}

	s.CongestionControl = models.BandwidthManagerCongestionControlCubic
	if d.statusParams.BandwidthManager.BBREnabled() {
		s.CongestionControl = models.BandwidthManagerCongestionControlBbr
	}

	devs, _ := datapathTables.SelectedDevices(d.statusParams.Devices, d.statusParams.DB.ReadTxn())
	s.Devices = datapathTables.DeviceNames(devs)
	return s
}

func (d *statusCollector) getRoutingStatus() *models.Routing {
	s := &models.Routing{
		IntraHostRoutingMode: models.RoutingIntraHostRoutingModeBPF,
		InterHostRoutingMode: models.RoutingInterHostRoutingModeTunnel,
		TunnelProtocol:       d.statusParams.TunnelConfig.EncapProtocol().String(),
	}
	if d.statusParams.DaemonConfig.EnableHostLegacyRouting {
		s.IntraHostRoutingMode = models.RoutingIntraHostRoutingModeLegacy
	}
	if d.statusParams.DaemonConfig.RoutingMode == option.RoutingModeNative {
		s.InterHostRoutingMode = models.RoutingInterHostRoutingModeNative
	}
	return s
}

func (d *statusCollector) getHostFirewallStatus() *models.HostFirewall {
	mode := models.HostFirewallModeDisabled
	if d.statusParams.DaemonConfig.EnableHostFirewall {
		mode = models.HostFirewallModeEnabled
	}
	devs, _ := datapathTables.SelectedDevices(d.statusParams.Devices, d.statusParams.DB.ReadTxn())
	return &models.HostFirewall{
		Mode:    mode,
		Devices: datapathTables.DeviceNames(devs),
	}
}

func (d *statusCollector) getClockSourceStatus() *models.ClockSource {
	return timestamp.GetClockSourceFromOptions()
}

func (d *statusCollector) getAttachModeStatus() models.AttachMode {
	mode := models.AttachModeTc
	if d.statusParams.DaemonConfig.EnableTCX && probes.HaveTCX() == nil {
		mode = models.AttachModeTcx
	}
	return mode
}

func (d *statusCollector) getDatapathModeStatus() models.DatapathMode {
	mode := models.DatapathModeVeth
	switch d.statusParams.DaemonConfig.DatapathMode {
	case datapathOption.DatapathModeNetkit:
		mode = models.DatapathModeNetkit
	case datapathOption.DatapathModeNetkitL2:
		mode = models.DatapathModeNetkitDashL2
	}
	return mode
}

func (d *statusCollector) getCNIChainingStatus() *models.CNIChainingStatus {
	mode := d.statusParams.CNIConfigManager.GetChainingMode()
	if len(mode) == 0 {
		mode = models.CNIChainingStatusModeNone
	}
	return &models.CNIChainingStatus{
		Mode: mode,
	}
}

func (d *statusCollector) getKubeProxyReplacementStatus(ctx context.Context) *models.KubeProxyReplacement {
	var mode string
	switch d.statusParams.DaemonConfig.KubeProxyReplacement {
	case option.KubeProxyReplacementTrue:
		mode = models.KubeProxyReplacementModeTrue
	case option.KubeProxyReplacementFalse:
		mode = models.KubeProxyReplacementModeFalse
	}

	devices, _ := datapathTables.SelectedDevices(d.statusParams.Devices, d.statusParams.DB.ReadTxn())
	devicesList := make([]*models.KubeProxyReplacementDeviceListItems0, len(devices))
	for i, dev := range devices {
		info := &models.KubeProxyReplacementDeviceListItems0{
			Name: dev.Name,
			IP:   make([]string, len(dev.Addrs)),
		}
		for _, addr := range dev.Addrs {
			info.IP = append(info.IP, addr.Addr.String())
		}
		devicesList[i] = info
	}

	features := &models.KubeProxyReplacementFeatures{
		NodePort:              &models.KubeProxyReplacementFeaturesNodePort{},
		HostPort:              &models.KubeProxyReplacementFeaturesHostPort{},
		ExternalIPs:           &models.KubeProxyReplacementFeaturesExternalIPs{},
		SocketLB:              &models.KubeProxyReplacementFeaturesSocketLB{},
		SocketLBTracing:       &models.KubeProxyReplacementFeaturesSocketLBTracing{},
		SessionAffinity:       &models.KubeProxyReplacementFeaturesSessionAffinity{},
		Nat46X64:              &models.KubeProxyReplacementFeaturesNat46X64{},
		BpfSocketLBHostnsOnly: d.statusParams.DaemonConfig.BPFSocketLBHostnsOnly,
	}
	if d.statusParams.DaemonConfig.EnableNodePort {
		features.NodePort.Enabled = true
		features.NodePort.Mode = strings.ToUpper(d.statusParams.DaemonConfig.NodePortMode)
		switch d.statusParams.DaemonConfig.LoadBalancerDSRDispatch {
		case option.DSRDispatchIPIP:
			features.NodePort.DsrMode = models.KubeProxyReplacementFeaturesNodePortDsrModeIPIP
		case option.DSRDispatchOption:
			features.NodePort.DsrMode = models.KubeProxyReplacementFeaturesNodePortDsrModeIPOptionExtension
		case option.DSRDispatchGeneve:
			features.NodePort.DsrMode = models.KubeProxyReplacementFeaturesNodePortDsrModeGeneve
		}
		if d.statusParams.DaemonConfig.NodePortMode == option.NodePortModeHybrid {
			//nolint:staticcheck
			features.NodePort.Mode = strings.Title(d.statusParams.DaemonConfig.NodePortMode)
		}
		features.NodePort.Algorithm = models.KubeProxyReplacementFeaturesNodePortAlgorithmRandom
		if d.statusParams.DaemonConfig.NodePortAlg == option.NodePortAlgMaglev {
			features.NodePort.Algorithm = models.KubeProxyReplacementFeaturesNodePortAlgorithmMaglev
			features.NodePort.LutSize = int64(d.statusParams.MaglevConfig.MaglevTableSize)
		}
		if d.statusParams.DaemonConfig.LoadBalancerAlgorithmAnnotation {
			features.NodePort.LutSize = int64(d.statusParams.MaglevConfig.MaglevTableSize)
		}
		if d.statusParams.DaemonConfig.NodePortAcceleration == option.NodePortAccelerationGeneric {
			features.NodePort.Acceleration = models.KubeProxyReplacementFeaturesNodePortAccelerationGeneric
		} else {
			features.NodePort.Acceleration = strings.Title(d.statusParams.DaemonConfig.NodePortAcceleration)
		}
		features.NodePort.PortMin = int64(d.statusParams.DaemonConfig.NodePortMin)
		features.NodePort.PortMax = int64(d.statusParams.DaemonConfig.NodePortMax)
	}
	if d.statusParams.DaemonConfig.EnableHostPort {
		features.HostPort.Enabled = true
	}
	if d.statusParams.DaemonConfig.EnableExternalIPs {
		features.ExternalIPs.Enabled = true
	}
	if d.statusParams.DaemonConfig.EnableSocketLB {
		features.SocketLB.Enabled = true
		features.SocketLBTracing.Enabled = true
	}
	if d.statusParams.DaemonConfig.EnableSessionAffinity {
		features.SessionAffinity.Enabled = true
	}
	if d.statusParams.DaemonConfig.NodePortNat46X64 || d.statusParams.DaemonConfig.EnableNat46X64Gateway {
		features.Nat46X64.Enabled = true
		gw := &models.KubeProxyReplacementFeaturesNat46X64Gateway{
			Enabled:  d.statusParams.DaemonConfig.EnableNat46X64Gateway,
			Prefixes: make([]string, 0),
		}
		if d.statusParams.DaemonConfig.EnableNat46X64Gateway {
			gw.Prefixes = append(gw.Prefixes, d.statusParams.DaemonConfig.IPv6NAT46x64CIDR)
		}
		features.Nat46X64.Gateway = gw

		svc := &models.KubeProxyReplacementFeaturesNat46X64Service{
			Enabled: d.statusParams.DaemonConfig.NodePortNat46X64,
		}
		features.Nat46X64.Service = svc
	}
	if d.statusParams.DaemonConfig.EnableNodePort {
		if d.statusParams.DaemonConfig.LoadBalancerAlgorithmAnnotation {
			features.Annotations = append(features.Annotations, annotation.ServiceLoadBalancingAlgorithm)
		}
		if d.statusParams.DaemonConfig.LoadBalancerModeAnnotation {
			features.Annotations = append(features.Annotations, annotation.ServiceForwardingMode)
		}
		features.Annotations = append(features.Annotations, annotation.ServiceNodeExposure)
		features.Annotations = append(features.Annotations, annotation.ServiceNodeSelectorExposure)
		features.Annotations = append(features.Annotations, annotation.ServiceTypeExposure)
		features.Annotations = append(features.Annotations, annotation.ServiceProxyDelegation)
		if d.statusParams.DaemonConfig.EnableSVCSourceRangeCheck {
			features.Annotations = append(features.Annotations, annotation.ServiceSourceRangesPolicy)
		}
		sort.Strings(features.Annotations)
	}

	var directRoutingDevice string
	drd, _ := d.statusParams.DirectRoutingDev.Get(ctx, d.statusParams.DB.ReadTxn())
	if drd != nil {
		directRoutingDevice = drd.Name
	}

	return &models.KubeProxyReplacement{
		Mode:                mode,
		Devices:             datapathTables.DeviceNames(devices),
		DeviceList:          devicesList,
		DirectRoutingDevice: directRoutingDevice,
		Features:            features,
	}
}

func (d *statusCollector) getBPFMapStatus() *models.BPFMapStatus {
	policyMaxEntries := int64(0)
	policyStatsMaxEntries := int64(0)
	if d.statusParams.PolicyMapFactory != nil {
		policyMaxEntries = int64(d.statusParams.PolicyMapFactory.PolicyMaxEntries())
		policyStatsMaxEntries = int64(d.statusParams.PolicyMapFactory.StatsMaxEntries())
	}

	return &models.BPFMapStatus{
		DynamicSizeRatio: d.statusParams.DaemonConfig.BPFMapsDynamicSizeRatio,
		Maps: []*models.BPFMapProperties{
			{
				Name: "Auth",
				Size: int64(d.statusParams.DaemonConfig.AuthMapEntries),
			},
			{
				Name: "Non-TCP connection tracking",
				Size: int64(d.statusParams.DaemonConfig.CTMapEntriesGlobalAny),
			},
			{
				Name: "TCP connection tracking",
				Size: int64(d.statusParams.DaemonConfig.CTMapEntriesGlobalTCP),
			},
			{
				Name: "Endpoints",
				Size: int64(lxcmap.MaxEntries),
			},
			{
				Name: "IP cache",
				Size: int64(ipcachemap.MaxEntries),
			},
			{
				Name: "IPv4 masquerading agent",
				Size: int64(ipmasqmap.MaxEntriesIPv4),
			},
			{
				Name: "IPv6 masquerading agent",
				Size: int64(ipmasqmap.MaxEntriesIPv6),
			},
			{
				Name: "IPv4 fragmentation",
				Size: int64(d.statusParams.DaemonConfig.FragmentsMapEntries),
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
				Name: "Ratelimit metrics",
				Size: int64(ratelimitmap.MaxMetricsEntries),
			},
			{
				Name: "NAT",
				Size: int64(d.statusParams.DaemonConfig.NATMapEntriesGlobal),
			},
			{
				Name: "Neighbor table",
				Size: int64(d.statusParams.DaemonConfig.NeighMapEntriesGlobal),
			},
			{
				Name: "Endpoint policy",
				Size: policyMaxEntries,
			},
			{
				Name: "Policy stats",
				Size: policyStatsMaxEntries,
			},
			{
				Name: "Session affinity",
				Size: int64(lbmap.AffinityMapMaxEntries),
			},
			{
				Name: "Sock reverse NAT",
				Size: int64(d.statusParams.DaemonConfig.SockRevNatEntries),
			},
		},
	}
}

func (d *statusCollector) getIdentityRange() *models.IdentityRange {
	s := &models.IdentityRange{
		MinIdentity: int64(identity.GetMinimalAllocationIdentity(d.statusParams.ClusterInfo.ID)),
		MaxIdentity: int64(identity.GetMaximumAllocationIdentity(d.statusParams.ClusterInfo.ID)),
	}

	return s
}

// dumpIPAM dumps in the form of a map, the list of
// reserved IPv4 and IPv6 addresses.
func (d *statusCollector) dumpIPAM() *models.IPAMStatus {
	allocv4, allocv6, st := d.statusParams.IPAM.Dump()
	status := &models.IPAMStatus{
		Status: st,
	}

	v4 := make([]string, 0, len(allocv4))
	for ip := range allocv4 {
		v4 = append(v4, ip)
	}

	v6 := make([]string, 0, len(allocv6))
	if allocv4 == nil {
		allocv4 = map[string]string{}
	}
	for ip, owner := range allocv6 {
		v6 = append(v6, ip)
		// merge allocv6 into allocv4
		allocv4[ip] = owner
	}

	if d.statusParams.DaemonConfig.EnableIPv4 {
		status.IPV4 = v4
	}

	if d.statusParams.DaemonConfig.EnableIPv6 {
		status.IPV6 = v6
	}

	status.Allocations = allocv4

	return status
}

// getStatus returns the daemon status. If brief is provided a minimal version
// of the StatusResponse is provided.
func (d *statusCollector) GetStatus(brief bool, requireK8sConnectivity bool) models.StatusResponse {
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
	case !d.allProbesInitialized:
		sr.Cilium = &models.Status{
			State: models.StatusStateWarning,
			Msg:   "Not all probes executed at least once",
		}
	case len(sr.Stale) > 0:
		msg := "Stale status data"
		sr.Cilium = &models.Status{
			State: models.StatusStateWarning,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.Kvstore != nil &&
		d.statusResponse.Kvstore.State != models.StatusStateOk &&
		d.statusResponse.Kvstore.State != models.StatusStateDisabled:
		msg := "Kvstore service is not ready: " + d.statusResponse.Kvstore.Msg
		sr.Cilium = &models.Status{
			State: d.statusResponse.Kvstore.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.ContainerRuntime != nil && d.statusResponse.ContainerRuntime.State != models.StatusStateOk:
		msg := "Container runtime is not ready: " + d.statusResponse.ContainerRuntime.Msg
		if d.statusResponse.ContainerRuntime.State == models.StatusStateDisabled {
			msg = "Container runtime is disabled"
		}
		sr.Cilium = &models.Status{
			State: d.statusResponse.ContainerRuntime.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusParams.Clientset.IsEnabled() && d.statusResponse.Kubernetes != nil && d.statusResponse.Kubernetes.State != models.StatusStateOk && requireK8sConnectivity:
		msg := "Kubernetes service is not ready: " + d.statusResponse.Kubernetes.Msg
		sr.Cilium = &models.Status{
			State: d.statusResponse.Kubernetes.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.CniFile != nil && d.statusResponse.CniFile.State == models.StatusStateFailure:
		msg := "Could not write CNI config file: " + d.statusResponse.CniFile.Msg
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

func (d *statusCollector) getProbes() []Probe {
	return []Probe{
		{
			Name: "kvstore",
			Probe: func(ctx context.Context) (any, error) {
				if d.statusParams.DaemonConfig.KVStore == "" {
					return &models.Status{State: models.StatusStateDisabled}, nil
				} else {
					return kvstore.Client().Status(), nil
				}
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err != nil {
					d.statusResponse.Kvstore = &models.Status{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}

				if kvstore, ok := status.Data.(*models.Status); ok {
					d.statusResponse.Kvstore = kvstore
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
				return d.statusParams.NodeDiscovery.Manager.ClusterSizeDependantInterval(10 * time.Second)
			},
			Probe: func(ctx context.Context) (any, error) {
				return d.getK8sStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				return d.dumpIPAM(), nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				return d.statusParams.MonitorAgent.State(), nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				clusterStatus := &models.ClusterStatus{
					Self: nodeTypes.GetAbsoluteNodeName(),
				}
				return clusterStatus, nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				return d.statusParams.CiliumHealth.GetStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				if d.statusParams.L7Proxy == nil {
					return nil, nil
				}
				return d.statusParams.L7Proxy.GetStatusModel(), nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				return controller.GetGlobalStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				if d.statusParams.Clustermesh == nil {
					return nil, nil
				}
				return d.statusParams.Clustermesh.Status(), nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				return d.statusParams.Hubble.Status(ctx), nil
			},
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				switch {
				case d.statusParams.DaemonConfig.EnableIPSec:
					return &models.EncryptionStatus{
						Mode: models.EncryptionStatusModeIPsec,
					}, nil
				case d.statusParams.DaemonConfig.EnableWireguard:
					var msg string
					status, err := d.statusParams.WireguardAgent.Status(false)
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
			OnStatusUpdate: func(status Status) {
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
			Probe: func(ctx context.Context) (any, error) {
				return d.getKubeProxyReplacementStatus(ctx), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.KubeProxyReplacement); ok {
						d.statusResponse.KubeProxyReplacement = s
					}
				}
			},
		},
		{
			Name: "auth-cert-provider",
			Probe: func(ctx context.Context) (any, error) {
				if d.statusParams.AuthManager == nil {
					return &models.Status{State: models.StatusStateDisabled}, nil
				}

				return d.statusParams.AuthManager.CertProviderStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.Status); ok {
						d.statusResponse.AuthCertificateProvider = s
					}
				}
			},
		},
		{
			Name: "cni-config",
			Probe: func(ctx context.Context) (any, error) {
				if d.statusParams.CNIConfigManager == nil {
					return nil, nil
				}
				return d.statusParams.CNIConfigManager.Status(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.Status); ok {
						d.statusResponse.CniFile = s
					}
				}
			},
		},
		{
			Name: "masquerading",
			Probe: func(ctx context.Context) (any, error) {
				return d.getMasqueradingStatus(ctx)
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.Masquerading); ok {
						d.statusResponse.Masquerading = s
					}
				}
			},
		},
		{
			Name: "bigtcp-v6",
			Probe: func(ctx context.Context) (any, error) {
				return d.getIPV6BigTCPStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.IPV6BigTCP); ok {
						d.statusResponse.IPV6BigTCP = s
					}
				}
			},
		},
		{
			Name: "bigtcp-v4",
			Probe: func(ctx context.Context) (any, error) {
				return d.getIPV4BigTCPStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.IPV4BigTCP); ok {
						d.statusResponse.IPV4BigTCP = s
					}
				}
			},
		},
		{
			Name: "bandwidth-manager",
			Probe: func(ctx context.Context) (any, error) {
				return d.getBandwidthManagerStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.BandwidthManager); ok {
						d.statusResponse.BandwidthManager = s
					}
				}
			},
		},
		{
			Name: "host-firewall",
			Probe: func(ctx context.Context) (any, error) {
				return d.getHostFirewallStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.HostFirewall); ok {
						d.statusResponse.HostFirewall = s
					}
				}
			},
		},
		{
			Name: "routing",
			Probe: func(ctx context.Context) (any, error) {
				return d.getRoutingStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.Routing); ok {
						d.statusResponse.Routing = s
					}
				}
			},
		},
		{
			Name: "clock-source",
			Probe: func(ctx context.Context) (any, error) {
				return d.getClockSourceStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.ClockSource); ok {
						d.statusResponse.ClockSource = s
					}
				}
			},
		},
		{
			Name: "bpf-maps",
			Probe: func(ctx context.Context) (any, error) {
				return d.getBPFMapStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.BPFMapStatus); ok {
						d.statusResponse.BpfMaps = s
					}
				}
			},
		},
		{
			Name: "cni-chaining",
			Probe: func(ctx context.Context) (any, error) {
				return d.getCNIChainingStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.CNIChainingStatus); ok {
						d.statusResponse.CniChaining = s
					}
				}
			},
		},
		{
			Name: "identity-range",
			Probe: func(ctx context.Context) (any, error) {
				return d.getIdentityRange(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.IdentityRange); ok {
						d.statusResponse.IdentityRange = s
					}
				}
			},
		},
		{
			Name: "SRv6",
			Probe: func(ctx context.Context) (any, error) {
				return d.getSRv6Status(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.Srv6); ok {
						d.statusResponse.Srv6 = s
					}
				}
			},
		},
		{
			Name: "attach-mode",
			Probe: func(ctx context.Context) (any, error) {
				return d.getAttachModeStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(models.AttachMode); ok {
						d.statusResponse.AttachMode = s
					}
				}
			},
		},
		{
			Name: "datapath-mode",
			Probe: func(ctx context.Context) (any, error) {
				return d.getDatapathModeStatus(), nil
			},
			OnStatusUpdate: func(status Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(models.DatapathMode); ok {
						d.statusResponse.DatapathMode = s
					}
				}
			},
		},
	}
}
