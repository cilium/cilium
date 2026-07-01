// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
)

type RoutePolicyReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type RoutePolicyReconcilerIn struct {
	cell.In

	Logger                  *slog.Logger
	DB                      *statedb.DB
	DesiredRoutePolicyTable statedb.Table[*bgpTables.DesiredRoutePolicy]
}

type RoutePolicyReconciler struct {
	logger                  *slog.Logger
	db                      *statedb.DB
	desiredRoutePolicyTable statedb.Table[*bgpTables.DesiredRoutePolicy]
	metadata                map[string]RoutePolicyReconcilerMetadata
}

type RoutePolicyReconcilerMetadata struct {
	RoutePolicies RoutePolicyMap
}

// routePolicyObjectKey is used to group policy statements with the same key value into a single route policy object.
type routePolicyObjectKey struct {
	Instance   string
	Peer       string
	PolicyType types.RoutePolicyType
}

func NewRoutePolicyReconciler(params RoutePolicyReconcilerIn) RoutePolicyReconcilerOut {
	return RoutePolicyReconcilerOut{
		Reconciler: &RoutePolicyReconciler{
			logger:                  params.Logger.With(types.ReconcilerLogField, RoutePolicyReconcilerName),
			db:                      params.DB,
			desiredRoutePolicyTable: params.DesiredRoutePolicyTable,
			metadata:                make(map[string]RoutePolicyReconcilerMetadata),
		},
	}
}

func (r *RoutePolicyReconciler) getMetadata(i *instance.BGPInstance) RoutePolicyReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *RoutePolicyReconciler) setMetadata(i *instance.BGPInstance, metadata RoutePolicyReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

func (r *RoutePolicyReconciler) Name() string {
	return RoutePolicyReconcilerName
}

func (r *RoutePolicyReconciler) Priority() int {
	return RoutePolicyReconcilerPriority
}

func (r *RoutePolicyReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = RoutePolicyReconcilerMetadata{
		RoutePolicies: make(RoutePolicyMap),
	}
	return nil
}

func (r *RoutePolicyReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *RoutePolicyReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}
	metadata := r.getMetadata(p.BGPInstance)

	desiredPolicies, err := r.desiredRoutePolicies(p.BGPInstance.Name)
	if err != nil {
		r.setMetadata(p.BGPInstance, metadata)
		return err
	}

	updatedPolicies, err := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
		Logger:          r.logger,
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredPolicies,
		CurrentPolicies: metadata.RoutePolicies,
	})
	metadata.RoutePolicies = updatedPolicies

	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *RoutePolicyReconciler) desiredRoutePolicies(instance string) (RoutePolicyMap, error) {
	rx := r.db.ReadTxn()

	// compile desired statements per routePolicyObjectKey
	desiredStatements := make(map[routePolicyObjectKey][]*bgpTables.DesiredRoutePolicy)
	for statement := range r.desiredRoutePolicyTable.List(rx, bgpTables.DesiredRoutePoliciesByInstance(instance)) {
		policyKey := getRoutePolicyObjectKey(statement)
		desiredStatements[policyKey] = append(desiredStatements[policyKey], statement)
	}

	// compile desired route policies
	desiredPolicies := make(RoutePolicyMap, len(desiredStatements))
	for policyKey, statements := range desiredStatements {
		policy, err := desiredRoutePolicyFromStatements(policyKey, statements)
		if err != nil {
			return nil, err
		}
		if policy != nil {
			desiredPolicies[policy.Name] = policy
		}
	}
	return desiredPolicies, nil
}

func desiredRoutePolicyFromStatements(policyKey routePolicyObjectKey, statements []*bgpTables.DesiredRoutePolicy) (*types.RoutePolicy, error) {
	if len(statements) == 0 {
		return nil, nil
	}

	// sort by priority and statement name
	sort.SliceStable(statements, func(i, j int) bool {
		if statements[i].Priority == statements[j].Priority {
			return statements[i].StatementName() < statements[j].StatementName()
		}
		return statements[i].Priority < statements[j].Priority
	})

	policy := &types.RoutePolicy{
		Name: routePolicyName(policyKey.Peer, policyKey.PolicyType),
		Type: policyKey.PolicyType,
	}
	for _, statement := range statements {
		if statement.Statement != nil {
			policy.Statements = append(policy.Statements, statement.Statement)
		}
	}
	return policy, nil
}

func getRoutePolicyObjectKey(policy *bgpTables.DesiredRoutePolicy) routePolicyObjectKey {
	return routePolicyObjectKey{
		Instance:   policy.Instance,
		Peer:       policy.Peer,
		PolicyType: policy.PolicyType,
	}
}

func routePolicyName(peer string, policyType types.RoutePolicyType) string {
	return fmt.Sprintf("peer-%s-%s", peer, policyType)
}
