// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// The adapters in this file replaces the [service.ServiceManager]
// implementation.  These are meant to be temporary until the uses of these
// interfaces have been migrated over to using the tables directly.

type adapterParams struct {
	cell.In

	Clientset    client.Clientset
	JobGroup     job.Group
	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	Config       loadbalancer.Config
	DB           *statedb.DB
	Services     statedb.Table[*loadbalancer.Service]
	Backends     statedb.Table[*loadbalancer.Backend]
	Frontends    statedb.Table[*loadbalancer.Frontend]
	Ops          *lbreconciler.BPFOps
	Writer       *writer.Writer
	TestConfig   *loadbalancer.TestConfig `optional:"true"`
}

// newAdapters constructs the ServiceCache and ServiceManager adapters
func newAdapters(p adapterParams) service.ServiceManager {
	sma := &serviceManagerAdapter{
		log:          p.Log,
		daemonConfig: p.DaemonConfig,
		db:           p.DB,
		services:     p.Services,
		frontends:    p.Frontends,
		writer:       p.Writer,
	}
	return sma
}

type serviceManagerAdapter struct {
	log          *slog.Logger
	daemonConfig *option.DaemonConfig
	db           *statedb.DB
	services     statedb.Table[*loadbalancer.Service]
	frontends    statedb.Table[*loadbalancer.Frontend]
	writer       *writer.Writer
}

// GetCurrentTs implements service.ServiceManager.
func (s *serviceManagerAdapter) GetCurrentTs() time.Time {
	// Used by kubeproxyhealthz.
	return time.Now()
}

// GetLastUpdatedTs implements service.ServiceManager.
func (s *serviceManagerAdapter) GetLastUpdatedTs() time.Time {
	// Used by kubeproxyhealthz. Unclear how important it is to have real last updated time here.
	// We could e.g. keep a timestamp behind an atomic in BPFOps to implement that.
	return time.Now()
}

// GetServiceNameByAddr implements service.ServiceReader.
func (s *serviceManagerAdapter) GetServiceNameByAddr(addr loadbalancer.L3n4Addr) (string, string, bool) {
	// Used by hubble.

	txn := s.db.ReadTxn()

	fe, _, found := s.frontends.Get(txn, loadbalancer.FrontendByAddress(addr))
	if !found {
		return "", "", false
	}
	return fe.Service.Name.Namespace, fe.Service.Name.Name, true
}

var _ service.ServiceManager = &serviceManagerAdapter{}
