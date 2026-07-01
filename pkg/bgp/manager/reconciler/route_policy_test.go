// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/agent"
	bgpcommands "github.com/cilium/cilium/pkg/bgp/commands"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	bgpmock "github.com/cilium/cilium/pkg/bgp/mock"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
)

type routePolicyTestFixture struct {
	hive       *ciliumhive.Hive
	instances  map[string]*instance.BGPInstance
	reconciler ConfigReconciler
}

func TestRoutePolicyReconciler(t *testing.T) {
	setup := func(t testing.TB, _ []string) *script.Engine {
		log := hivetest.Logger(t)
		f := newRoutePolicyTestFixture(t)

		t.Cleanup(func() {
			if err := f.hive.Stop(log, context.Background()); err != nil {
				t.Errorf("stopping hive: %v", err)
			}
		})

		cmds, err := f.hive.ScriptCommands(log)
		if err != nil {
			t.Fatalf("ScriptCommands: %v", err)
		}
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		maps.Insert(cmds, maps.All(testReconcilerScriptCommands(f.reconciler, f.instances)))

		return &script.Engine{
			Cmds: cmds,
		}
	}
	scripttest.Test(t, t.Context(), setup, nil, "testdata/route-policy*.txtar")
}

func newRoutePolicyTestFixture(t testing.TB) *routePolicyTestFixture {
	t.Helper()

	f := &routePolicyTestFixture{
		instances: make(map[string]*instance.BGPInstance),
	}
	f.hive = ciliumhive.New(
		cell.Provide(
			bgpTables.NewDesiredRoutePoliciesTable,
			statedb.RWTable[*bgpTables.DesiredRoutePolicy].ToTable,

			f.mockBGPRouterManager,
		),
		bgpcommands.Cell,

		cell.Invoke(func(in RoutePolicyReconcilerIn) {
			out := NewRoutePolicyReconciler(in)
			f.reconciler = out.Reconciler
		}),
	)
	return f
}

func (f *routePolicyTestFixture) mockBGPRouterManager() agent.BGPRouterManager {
	return &bgpmock.MockBGPRouterManager{
		GetRoutePolicies_: func(ctx context.Context, req *agent.GetRoutePoliciesRequest) (*agent.GetRoutePoliciesResponse, error) {
			routePolicies := make([]agent.InstanceRoutePolicies, 0)
			for instanceName, instance := range f.instances {
				if req.InstanceName != "" && req.InstanceName != instanceName {
					continue
				}
				rs, err := instance.Router.GetRoutePolicies(ctx)
				if err != nil {
					return nil, err
				}
				routePolicies = append(routePolicies, agent.InstanceRoutePolicies{
					Name:          instance.Name,
					RoutePolicies: rs.Policies,
				})
			}
			return &agent.GetRoutePoliciesResponse{
				Instances: routePolicies,
			}, nil
		},
	}
}
