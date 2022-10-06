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
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	_ "github.com/cilium/proxy/go/envoy/type/matcher/v3"
)

const (
	labelPrefix = "k8s-app="
)

const (
	DefaultCiliumLabelSelector               = labelPrefix + "cilium"
	DefaultCiliumOperatorLabelSelector       = "io.cilium/app=operator"
	DefaultClustermeshApiserverLabelSelector = labelPrefix + "clustermesh-apiserver"
	DefaultDebug                             = false
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
)

var (
	// DefaultWorkerCount is initialized to the machine's available CPUs.
	DefaultWorkerCount = runtime.NumCPU()

	// DefaultCiliumNamespaces will be used to attempt to autodetect what namespace Cilium is installed in
	// unless otherwise specified.
	DefaultCiliumNamespaces = []string{"kube-system", "cilium"}
)
