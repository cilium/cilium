// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

var demoHealthChecker = cell.Module(
	"demo-healthchecker",
	"Example backend health checker",

	cell.Invoke(registerHealthChecker),
)

type healthCheckerParams struct {
	cell.In

	Config   Config
	Log      *slog.Logger
	JobGroup job.Group
	Backends statedb.Table[*Backend]
	Writer   *Writer
	DB       *statedb.DB
}

func registerHealthChecker(p healthCheckerParams) {
	if !p.Config.EnableExperimentalLB {
		return
	}
	p.JobGroup.Add(
		job.OneShot(
			"healthchecker",
			(&healthChecker{p}).loop,
		),
	)
}

type healthChecker struct {
	healthCheckerParams
}

func (h *healthChecker) loop(ctx context.Context, health cell.Health) error {
	wtxn := h.DB.WriteTxn(h.Backends)
	backendChanges, err := h.Backends.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return fmt.Errorf("failed to register for backend changes: %w", err)
	}
	defer backendChanges.Close()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	targets := sets.New[loadbalancer.L3n4Addr]()
	unhealthy := 0

	for {
		health.OK(fmt.Sprintf("Waiting (%d targets, %d unhealthy)", len(targets), unhealthy))
		select {
		case <-ctx.Done():
			return nil
		case <-backendChanges.Watch(h.DB.ReadTxn()):
			for change, _, ok := backendChanges.Next(); ok; change, _, ok = backendChanges.Next() {
				be := change.Object
				if !change.Deleted && shouldHealthCheck(be) {
					targets.Insert(be.L3n4Addr)
				} else {
					targets.Delete(be.L3n4Addr)
				}
			}
		case <-ticker.C:
			health.OK(fmt.Sprintf("Health checking %d targets", len(targets)))

			unhealthy = 0
			healthy := map[loadbalancer.L3n4Addr]bool{}
			for target := range targets {
				var addr string
				if target.IsIPv6() {
					addr = fmt.Sprintf("[%s]:%d", target.AddrCluster.Addr(), target.Port)
				} else {
					addr = fmt.Sprintf("%s:%d", target.AddrCluster.Addr(), target.Port)
				}
				conn, err := net.Dial("tcp", addr)
				if err == nil {
					h.Log.Debug("Dialing succeeded", "address", addr)
					conn.Close()
					healthy[target] = true
				} else {
					h.Log.Debug("Dialing failed", "address", addr, "error", err)
					unhealthy++
					healthy[target] = false
				}
			}

			wtxn := h.Writer.WriteTxn()
			for target, isHealthy := range healthy {
				h.Writer.SetBackendHealth(wtxn, target, isHealthy)
			}
			wtxn.Commit()
		}

	}
}

func shouldHealthCheck(be *Backend) bool {
	return be.L3n4Addr.Protocol == loadbalancer.TCP &&
		(be.State == loadbalancer.BackendStateActive || be.State == loadbalancer.BackendStateQuarantined)
}
