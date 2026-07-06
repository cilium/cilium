// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/tables"
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
	DesiredRoutePolicyTable statedb.Table[*tables.DesiredRoutePolicy]
}

type RoutePolicyReconciler struct {
	logger                  *slog.Logger
	db                      *statedb.DB
	desiredRoutePolicyTable statedb.Table[*tables.DesiredRoutePolicy]
	metadata                map[string]RoutePolicyReconcilerMetadata
}

type RoutePolicyReconcilerMetadata struct {
	RoutePolicies RoutePolicyMap

	DesiredChanges            statedb.ChangeIterator[*tables.DesiredRoutePolicy]
	DesiredChangesInitialized bool
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
	desiredPolicies, currentPolicies, err := r.routePoliciesToReconcile(p, &metadata)
	if err != nil {
		return err
	}
	updatedPolicies, err := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
		Logger:          r.logger,
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredPolicies,
		CurrentPolicies: currentPolicies,
	})

	// Update route policies in the metadata. Note that updatedPolicies may contain just a subset of all policies
	// in case diff reconciliation, the remaining policies need to stay untouched.
	for policyName := range currentPolicies {
		delete(metadata.RoutePolicies, policyName) // ensure stale polices are always deleted
	}
	maps.Copy(metadata.RoutePolicies, updatedPolicies)

	if err != nil {
		// The change iterator has already advanced, so the retry must do a full reconciliation.
		metadata.DesiredChangesInitialized = false
	}
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *RoutePolicyReconciler) routePoliciesToReconcile(p ReconcileParams, metadata *RoutePolicyReconcilerMetadata) (desired, current RoutePolicyMap, err error) {
	if !metadata.DesiredChangesInitialized {
		return r.fullReconciliationRoutePolicies(p, metadata)
	}
	return r.diffReconciliationRoutePolicies(p, metadata)
}

func (r *RoutePolicyReconciler) fullReconciliationRoutePolicies(p ReconcileParams, metadata *RoutePolicyReconcilerMetadata) (desired, current RoutePolicyMap, err error) {
	tx := r.db.WriteTxn(r.desiredRoutePolicyTable)
	metadata.DesiredChanges, err = r.desiredRoutePolicyTable.Changes(tx)
	if err != nil {
		tx.Abort()
		return nil, nil, fmt.Errorf("error subscribing to desired route policy changes: %w", err)
	}
	rx := tx.Commit()
	metadata.DesiredChangesInitialized = true

	// compile all desired statements per policy object key
	desiredStatements := make(map[tables.DesiredRoutePolicyObjectKey][]*tables.DesiredRoutePolicy)
	changes, _ := metadata.DesiredChanges.Next(rx) // the initial Next() call will emit all existing statements
	for change := range changes {
		if change.Deleted {
			continue // this should not really happen for listing initial changes, skip just in case
		}
		statement := change.Object
		if statement.Instance != p.BGPInstance.Name {
			continue
		}
		policyKey := statement.GetPolicyObjectKey()
		desiredStatements[policyKey] = append(desiredStatements[policyKey], statement)
	}

	desired, err = routePolicyMapFromStatements(desiredStatements)
	current = metadata.RoutePolicies // all previously reconciled route policies
	return
}

func (r *RoutePolicyReconciler) diffReconciliationRoutePolicies(p ReconcileParams, metadata *RoutePolicyReconcilerMetadata) (desired, current RoutePolicyMap, err error) {
	if !metadata.DesiredChangesInitialized {
		return nil, nil, fmt.Errorf("BUG: desired route policy changes tracker not initialized, cannot perform diff reconciliation")
	}

	// list all statements that changed since last reconciliation and collect list of all modified policies
	rx := r.db.ReadTxn()
	changes, _ := metadata.DesiredChanges.Next(rx)
	changedPolicies := sets.New[tables.DesiredRoutePolicyObjectKey]()
	for change := range changes {
		statement := change.Object
		if statement.Instance == p.BGPInstance.Name {
			changedPolicies.Insert(statement.GetPolicyObjectKey())
		}
	}

	// For each modified policy collect:
	//  - all desired statements,
	//  - current (previously reconciled) policy from the metadata.
	// This will also handle policy deletion - for deleted policies,
	// desired statements will be empty, but current will emit the old policy.
	desiredStatements := make(map[tables.DesiredRoutePolicyObjectKey][]*tables.DesiredRoutePolicy)
	current = make(RoutePolicyMap, len(changedPolicies))
	for policyKey := range changedPolicies {
		policyName := routePolicyName(policyKey.Peer, policyKey.PolicyType)
		// desired statements from statedb
		for statement := range r.desiredRoutePolicyTable.List(rx, tables.DesiredRoutePoliciesByPolicyObject(policyKey)) {
			desiredStatements[policyKey] = append(desiredStatements[policyKey], statement)
		}
		// current (previously reconciled) policy from the metadata
		if policy, exists := metadata.RoutePolicies[policyName]; exists {
			current[policyName] = policy
		}
	}

	desired, err = routePolicyMapFromStatements(desiredStatements)
	return
}

func routePolicyMapFromStatements(desiredStatements map[tables.DesiredRoutePolicyObjectKey][]*tables.DesiredRoutePolicy) (RoutePolicyMap, error) {
	desiredPolicies := make(RoutePolicyMap, len(desiredStatements))
	for policyKey, statements := range desiredStatements {
		policy, err := routePolicyFromStatements(policyKey, statements)
		if err != nil {
			return nil, err
		}
		if policy != nil {
			desiredPolicies[policy.Name] = policy
		}
	}
	return desiredPolicies, nil
}

func routePolicyFromStatements(policyKey tables.DesiredRoutePolicyObjectKey, statements []*tables.DesiredRoutePolicy) (*types.RoutePolicy, error) {
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

func routePolicyName(peer string, policyType types.RoutePolicyType) string {
	return fmt.Sprintf("peer-%s-%s", peer, policyType)
}
