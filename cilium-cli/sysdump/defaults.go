// Copyright 2021 Authors of Cilium
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
	DefaultCiliumLabelSelector         = labelPrefix + "cilium"
	DefaultCiliumNamespace             = "kube-system"
	DefaultCiliumOperatorLabelSelector = "io.cilium/app=operator"
	DefaultCiliumOperatorNamespace     = DefaultCiliumNamespace
	DefaultDebug                       = false
	DefaultHubbleLabelSelector         = labelPrefix + "hubble"
	DefaultHubbleNamespace             = DefaultCiliumNamespace
	DefaultHubbleFlowsCount            = 10000
	DefaultHubbleFlowsTimeout          = 5 * time.Second
	DefaultHubbleRelayLabelSelector    = labelPrefix + "hubble-relay"
	DefaultHubbleRelayNamespace        = DefaultCiliumNamespace
	DefaultHubbleUILabelSelector       = labelPrefix + "hubble-ui"
	DefaultHubbleUINamespace           = DefaultCiliumNamespace
	DefaultLargeSysdumpAbortTimeout    = 5 * time.Second
	DefaultLargeSysdumpThreshold       = 20
	DefaultLogsSinceTime               = 8760 * time.Hour // 1y
	DefaultLogsLimitBytes              = 1073741824       // 1GiB
	DefaultNodeList                    = ""
	DefaultQuick                       = false
	DefaultOutputFileName              = "cilium-sysdump-<ts>" // "<ts>" will be replaced with the timestamp
)

var (
	// DefaultWorkerCount is initialized to the machine's available CPUs.
	DefaultWorkerCount = runtime.NumCPU()

	// DefaultWriter points to os.Stdout by default.
	DefaultWriter = os.Stdout
)
