// Copyright 2019 Authors of Cilium
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

package datapath

import (
	"context"
	"io"
	"net"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/lock"
)

// Loader is an interface to abstract out loading of datapath programs.
type Loader interface {
	CallsMapPath(id uint16) string
	CompileAndLoad(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) error
	CompileOrLoad(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) error
	ReloadDatapath(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) error
	EndpointHash(cfg EndpointConfiguration) (string, error)
	DeleteDatapath(ctx context.Context, ifName, direction string) error
	Unload(ep Endpoint)
	Reinitialize(ctx context.Context, o BaseProgramOwner, deviceMTU int, iptMgr IptablesManager, p Proxy) error
}

// BaseProgramOwner is any type for which a loader is building base programs.
type BaseProgramOwner interface {
	DeviceConfiguration
	GetCompilationLock() *lock.RWMutex
	Datapath() Datapath
	LocalConfig() *LocalNodeConfiguration
	SetPrefilter(pf PreFilter)
}

// PreFilter an interface for an XDP pre-filter.
type PreFilter interface {
	WriteConfig(fw io.Writer)
	Dump(to []string) ([]string, int64)
	Insert(revision int64, cidrs []net.IPNet) error
	Delete(revision int64, cidrs []net.IPNet) error
}

// Proxy is any type which installs rules related to redirecting traffic to
// a proxy.
type Proxy interface {
	ReinstallRules()
}

// IptablesManager manages iptables rules.
type IptablesManager interface {
	// InstallProxyRules creates the necessary datapath config (e.g., iptables
	// rules for redirecting host proxy traffic on a specific ProxyPort)
	InstallProxyRules(proxyPort uint16, ingress bool, name string) error

	// RemoveProxyRules creates the necessary datapath config (e.g., iptables
	// rules for redirecting host proxy traffic on a specific ProxyPort)
	RemoveProxyRules(proxyPort uint16, ingress bool, name string) error

	// SupportsOriginalSourceAddr tells if the datapath supports
	// use of original source addresses in proxy upstream
	// connections.
	SupportsOriginalSourceAddr() bool
	RemoveRules(quiet bool)
	InstallRules(ifName string) error
	TransientRulesStart(ifName string) error
	TransientRulesEnd(quiet bool)
}
