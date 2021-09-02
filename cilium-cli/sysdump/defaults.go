// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package sysdump

import (
	"os"
	"runtime"
	"time"
)

const (
	labelPrefix = "k8s-app="
)

const (
	DefaultCiliumLabelSelector               = labelPrefix + "cilium"
	DefaultCiliumNamespace                   = "kube-system"
	DefaultCiliumOperatorLabelSelector       = "io.cilium/app=operator"
	DefaultCiliumOperatorNamespace           = DefaultCiliumNamespace
	DefaultClustermeshApiserverLabelSelector = "k8s-app=clustermesh-apiserver"
	DefaultClustermeshApiserverLabelSelector = labelPrefix + "clustermesh-apiserver"
	DefaultDebug                             = false
	DefaultHubbleLabelSelector               = labelPrefix + "hubble"
	DefaultHubbleNamespace                   = DefaultCiliumNamespace
	DefaultHubbleFlowsCount                  = 10000
	DefaultHubbleFlowsTimeout                = 5 * time.Second
	DefaultHubbleRelayLabelSelector          = labelPrefix + "hubble-relay"
	DefaultHubbleRelayNamespace              = DefaultCiliumNamespace
	DefaultHubbleUILabelSelector             = labelPrefix + "hubble-ui"
	DefaultHubbleUINamespace                 = DefaultCiliumNamespace
	DefaultLargeSysdumpAbortTimeout          = 5 * time.Second
	DefaultLargeSysdumpThreshold             = 20
	DefaultLogsSinceTime                     = 8760 * time.Hour // 1y
	DefaultLogsLimitBytes                    = 1073741824       // 1GiB
	DefaultNodeList                          = ""
	DefaultQuick                             = false
	DefaultOutputFileName                    = "cilium-sysdump-<ts>" // "<ts>" will be replaced with the timestamp
)

var (
	// DefaultWorkerCount is initialized to the machine's available CPUs.
	DefaultWorkerCount = runtime.NumCPU()

	// DefaultWriter points to os.Stdout by default.
	DefaultWriter = os.Stdout
)
