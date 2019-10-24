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

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
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
	Reinitialize(ctx context.Context, o BaseProgramOwner, deviceMTU int, iptMgr RulesManager, p Proxy, r RouteReserver) error
}

// BaseProgramOwner is any type for which a loader is building base programs.
type BaseProgramOwner interface {
	DeviceConfiguration
	GetCompilationLock() *lock.RWMutex
	Datapath() Datapath
	LocalConfig() *LocalNodeConfiguration
	SetPrefilter(pf *prefilter.PreFilter)
}

// RouteReserver is any type which is responsible for installing local routes.
type RouteReserver interface {
	ReserveLocalRoutes()
}

// Proxy is any type which installs rules related to redirecting traffic to
// a proxy.
type Proxy interface {
	ReinstallRules()
}

// RulesManager manages iptables rules.
type RulesManager interface {
	RemoveRules()
	InstallRules(ifName string) error
	TransientRulesStart(ifName string) error
	TransientRulesEnd(quiet bool)
}
