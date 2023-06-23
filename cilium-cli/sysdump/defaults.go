// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"runtime"
	"time"

	// for envoy unmarshalling
	_ "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	_ "github.com/cilium/proxy/go/envoy/config/core/v3"
	_ "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	_ "github.com/cilium/proxy/go/envoy/config/listener/v3"
	_ "github.com/cilium/proxy/go/envoy/config/route/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/ext_authz/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/local_ratelimit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/ratelimit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/set_metadata/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/connection_limit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/ext_authz/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/local_ratelimit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/ratelimit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/sni_cluster/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/http/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/tcp/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	_ "github.com/cilium/proxy/go/envoy/type/matcher/v3"
)

const (
	labelPrefix = "k8s-app="
)

const (
	DefaultCiliumLabelSelector               = labelPrefix + "cilium"
	DefaultCiliumEnvoyLabelSelector          = labelPrefix + "cilium-envoy"
	DefaultCiliumOperatorLabelSelector       = "io.cilium/app=operator"
	DefaultClustermeshApiserverLabelSelector = labelPrefix + "clustermesh-apiserver"
	DefaultDebug                             = false
	DefaultProfiling                         = true
	DefaultHubbleLabelSelector               = labelPrefix + "hubble"
	DefaultHubbleFlowsCount                  = 10000
	DefaultHubbleFlowsTimeout                = 5 * time.Second
	DefaultHubbleRelayLabelSelector          = labelPrefix + "hubble-relay"
	DefaultHubbleUILabelSelector             = labelPrefix + "hubble-ui"
	DefaultLargeSysdumpAbortTimeout          = 5 * time.Second
	DefaultLargeSysdumpThreshold             = 20
	DefaultLogsSinceTime                     = 8760 * time.Hour // 1y
	DefaultLogsLimitBytes                    = 1073741824       // 1GiB
	DefaultNodeList                          = ""
	DefaultQuick                             = false
	DefaultOutputFileName                    = "cilium-sysdump-<ts>" // "<ts>" will be replaced with the timestamp
	DefaultDetectGopsPID                     = false
	DefaultCNIConfigDirectory                = "/etc/cni/net.d/"
	DefaultCNIConfigMapName                  = "cni-configuration"
	DefaultTetragonNamespace                 = "kube-system"
	DefaultTetragonLabelSelector             = "app.kubernetes.io/name=tetragon"
	DefaultTetragonAgentContainerName        = "tetragon"
	DefaultTetragonBugtoolPrefix             = "tetragon-bugtool"
	DefaultTetragonCLICommand                = "tetra"
	DefaultTetragonTracingPolicy             = "tetragontracingpolicy-<ts>.yaml"
	DefaultTetragonTracingPolicyNamespaced   = "tetragontracingpolicynamespaced-<ts>.yaml"
)

var (
	// DefaultWorkerCount is initialized to the machine's available CPUs.
	DefaultWorkerCount = runtime.NumCPU()

	// DefaultCopyRetryLimit limits retries done while copying files from pods
	DefaultCopyRetryLimit = 100

	// DefaultCiliumNamespaces will be used to attempt to autodetect what namespace Cilium is installed in
	// unless otherwise specified.
	DefaultCiliumNamespaces = []string{"kube-system", "cilium"}

	// DefaultCiliumSPIRENamespaces will be used to attempt to autodetect what namespace Cilium SPIRE is installed in
	// unless otherwise specified.
	DefaultCiliumSPIRENamespaces = []string{"kube-system", "cilium", "cilium-spire"}
)
