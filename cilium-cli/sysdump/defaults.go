// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"runtime"
	"time"
)

const (
	labelPrefix = "k8s-app="
)

const (
	DefaultCiliumLabelSelector               = labelPrefix + "cilium"
	DefaultCiliumEnvoyLabelSelector          = labelPrefix + "cilium-envoy"
	DefaultCiliumOperatorLabelSelector       = "io.cilium/app=operator"
	DefaultClustermeshApiserverLabelSelector = labelPrefix + "clustermesh-apiserver"
	DefaultCiliumNodeInitLabelSelector       = "app=cilium-node-init"
	DefaultCiliumSpireAgentLabelSelector     = "app=spire-agent"
	DefaultCiliumSpireServerLabelSelector    = "app=spire-server"
	DefaultDebug                             = false
	DefaultProfiling                         = true
	DefaultTracing                           = false
	DefaultHubbleLabelSelector               = labelPrefix + "hubble"
	DefaultHubbleFlowsCount                  = 10000
	DefaultHubbleFlowsTimeout                = 5 * time.Second
	DefaultHubbleRelayLabelSelector          = labelPrefix + "hubble-relay"
	DefaultHubbleUILabelSelector             = labelPrefix + "hubble-ui"
	DefaultHubbleGenerateCertsLabelSelector  = labelPrefix + "hubble-generate-certs"
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
	DefaultTetragonOperatorLabelSelector     = "app.kubernetes.io/name=tetragon-operator"
	DefaultTetragonAgentContainerName        = "tetragon"
	DefaultTetragonConfigMapName             = "tetragon-config"
	DefaultTetragonBugtoolPrefix             = "tetragon-bugtool"
	DefaultTetragonCLICommand                = "tetra"
	DefaultTetragonPodInfo                   = "tetragonpodinfo-<ts>.yaml"
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
