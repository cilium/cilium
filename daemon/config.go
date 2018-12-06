// Copyright 2018 Authors of Cilium
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

package main

import (
	"strings"

	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/viper"
)

func getIPv4Enabled() bool {
	if viper.GetBool(option.LegacyDisableIPv4Name) {
		return false
	}

	return viper.GetBool(option.EnableIPv4Name)
}

func populateConfig() {

	option.Config.AccessLog = viper.GetString(option.AccessLog)
	option.Config.AgentLabels = viper.GetStringSlice(option.AgentLabels)
	option.Config.AllowLocalhost = viper.GetString(option.AllowLocalhost)
	option.Config.AutoIPv6NodeRoutes = viper.GetBool(option.AutoIPv6NodeRoutesName)
	option.Config.BPFCompilationDebug = viper.GetBool(option.BPFCompileDebugName)
	option.Config.CTMapEntriesGlobalTCP = viper.GetInt(option.CTMapEntriesGlobalTCPName)
	option.Config.CTMapEntriesGlobalAny = viper.GetInt(option.CTMapEntriesGlobalAnyName)
	option.Config.BPFRoot = viper.GetString(option.BPFRoot)
	option.Config.CGroupRoot = viper.GetString(option.CGroupRoot)
	option.Config.ClusterID = viper.GetInt(option.ClusterIDName)
	option.Config.ClusterName = viper.GetString(option.ClusterName)
	option.Config.ClusterMeshConfig = viper.GetString(option.ClusterMeshConfigName)
	option.Config.ConntrackGarbageCollectorInterval = viper.GetInt(option.ConntrackGarbageCollectorInterval)
	option.Config.Debug = viper.GetBool(option.DebugArg)
	option.Config.DebugVerbose = viper.GetStringSlice(option.DebugVerbose)
	option.Config.Device = viper.GetString(option.Device)
	option.Config.DisableConntrack = viper.GetBool(option.DisableConntrack)
	option.Config.EnableIPv4 = getIPv4Enabled()
	option.Config.EnableIPv6 = viper.GetBool(option.EnableIPv6Name)
	option.Config.DevicePreFilter = viper.GetString(option.PrefilterDevice)
	option.Config.DisableCiliumEndpointCRD = viper.GetBool(option.DisableCiliumEndpointCRDName)
	option.Config.DisableK8sServices = viper.GetBool(option.DisableK8sServices)
	option.Config.DockerEndpoint = viper.GetString(option.Docker)
	option.Config.EnablePolicy = strings.ToLower(viper.GetString(option.EnablePolicy))
	option.Config.EnableTracing = viper.GetBool(option.EnableTracing)
	option.Config.EnvoyLogPath = viper.GetString(option.EnvoyLog)
	option.Config.HTTPIdleTimeout = viper.GetInt(option.HTTPIdleTimeout)
	option.Config.HTTPMaxGRPCTimeout = viper.GetInt(option.HTTPMaxGRPCTimeout)
	option.Config.HTTPRequestTimeout = viper.GetInt(option.HTTPRequestTimeout)
	option.Config.HTTPRetryCount = viper.GetInt(option.HTTPRetryCount)
	option.Config.HTTPRetryTimeout = viper.GetInt(option.HTTPRetryTimeout)
	option.Config.IPv4ClusterCIDRMaskSize = viper.GetInt(option.IPv4ClusterCIDRMaskSize)
	option.Config.IPv4Range = viper.GetString(option.IPv4Range)
	option.Config.IPv4NodeAddr = viper.GetString(option.IPv4NodeAddr)
	option.Config.IPv4ServiceRange = viper.GetString(option.IPv4ServiceRange)
	option.Config.IPv6ClusterAllocCIDR = viper.GetString(option.IPv6ClusterAllocCIDRName)
	option.Config.IPv6NodeAddr = viper.GetString(option.IPv6NodeAddr)
	option.Config.IPv6Range = viper.GetString(option.IPv6Range)
	option.Config.IPv6ServiceRange = viper.GetString(option.IPv6ServiceRange)
	option.Config.K8sAPIServer = viper.GetString(option.K8sAPIServer)
	option.Config.K8sKubeConfigPath = viper.GetString(option.K8sKubeConfigPath)
	option.Config.K8sRequireIPv4PodCIDR = viper.GetBool(option.K8sRequireIPv4PodCIDRName)
	option.Config.K8sRequireIPv6PodCIDR = viper.GetBool(option.K8sRequireIPv6PodCIDRName)
	option.Config.KeepTemplates = viper.GetBool(option.KeepBPFTemplates)
	option.Config.KeepConfig = viper.GetBool(option.KeepConfig)
	option.Config.KVStore = viper.GetString(option.KVStore)
	option.Config.LabelPrefixFile = viper.GetString(option.LabelPrefixFile)
	option.Config.Labels = viper.GetStringSlice(option.Labels)
	option.Config.LBInterface = viper.GetString(option.LB)
	option.Config.LibDir = viper.GetString(option.LibDir)
	option.Config.LogDriver = viper.GetStringSlice(option.LogDriver)
	option.Config.LogSystemLoadConfig = viper.GetBool(option.LogSystemLoadConfigName)
	option.Config.Logstash = viper.GetBool(option.Logstash)
	option.Config.Masquerade = viper.GetBool(option.Masquerade)
	option.Config.ModePreFilter = viper.GetString(option.PrefilterMode)
	option.Config.MonitorAggregation = viper.GetString(option.MonitorAggregationName)
	option.Config.MonitorQueueSize = viper.GetInt(option.MonitorQueueSizeName)
	option.Config.MTU = viper.GetInt(option.MTUName)
	option.Config.NAT46Range = viper.GetString(option.NAT46Range)
	option.Config.PProf = viper.GetBool(option.PProf)
	option.Config.PrependIptablesChains = viper.GetBool(option.PrependIptablesChainsName)
	option.Config.PrometheusServeAddr = getPrometheusServerAddr()
	option.Config.ProxyConnectTimeout = viper.GetInt(option.ProxyConnectTimeout)
	option.Config.RestoreState = viper.GetBool(option.Restore)
	option.Config.RunDir = viper.GetString(option.StateDir)
	option.Config.SidecarIstioProxyImage = viper.GetString(option.SidecarIstioProxyImage)
	option.Config.UseSingleClusterRoute = viper.GetBool(option.SingleClusterRouteName)
	option.Config.SocketPath = viper.GetString(option.SocketPath)
	option.Config.SockopsEnable = viper.GetBool(option.SockopsEnableName)
	option.Config.ToFQDNsEnablePoller = viper.GetBool(option.ToFQDNsEnablePoller)
	option.Config.ToFQDNsMinTTL = viper.GetInt(option.ToFQDNsMinTTL)
	option.Config.ToFQDNsProxyPort = viper.GetInt(option.ToFQDNsProxyPort)
	option.Config.TracePayloadlen = viper.GetInt(option.TracePayloadlen)
	option.Config.Tunnel = viper.GetString(option.TunnelName)
	option.Config.Version = viper.GetString(option.Version)
	option.Config.Workloads = viper.GetStringSlice(option.ContainerRuntime)

	// Map options
	if m := viper.GetStringMapString(option.ContainerRuntimeEndpoint); len(m) != 0 {
		option.Config.ContainerRuntimeEndpoint = m
	}

	if m := viper.GetStringMapString(option.FixedIdentityMapping); len(m) != 0 {
		option.Config.FixedIdentityMapping = m
	}

	if m := viper.GetStringMapString(option.KVStoreOpt); len(m) != 0 {
		option.Config.KVStoreOpt = m
	}

	if m := viper.GetStringMapString(option.LogOpt); len(m) != 0 {
		option.Config.LogOpt = m
	}

	// Hidden options
	option.Config.ConfigFile = viper.GetString(option.ConfigFile)
	option.Config.HTTP403Message = viper.GetString(option.HTTP403Message)
	option.Config.DisableEnvoyVersionCheck = viper.GetBool(option.DisableEnvoyVersionCheck)
	option.Config.K8sNamespace = viper.GetString(option.K8sNamespaceName)
	option.Config.K8sLegacyHostAllowsWorld = viper.GetString(option.K8sLegacyHostAllowsWorld)
	option.Config.MaxControllerInterval = viper.GetInt(option.MaxCtrlIntervalName)
	option.Config.SidecarHTTPProxy = viper.GetBool(option.SidecarHTTPProxy)
	option.Config.CMDRefDir = viper.GetString(option.CMDRef)
}

func getPrometheusServerAddr() string {
	promAddr := viper.GetString(option.PrometheusServeAddr)
	if promAddr == "" {
		return viper.GetString("prometheus-serve-addr-deprecated")
	}
	return promAddr
}
