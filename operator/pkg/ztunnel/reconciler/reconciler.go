// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"iter"
	"log/slog"

	"github.com/cilium/cilium/operator/auth/spire"
	"github.com/cilium/cilium/pkg/ztunnel/table"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

type params struct {
	cell.In

	DB                     *statedb.DB
	ServiceAccountTable    statedb.Table[ServiceAccount]
	EnrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
	SpireClient            *spire.Client
	Logger                 *slog.Logger
	Lifecycle              cell.Lifecycle
}

type EnrollmentReconciler struct {
	db                     *statedb.DB
	logger                 *slog.Logger
	spireClient            *spire.Client
	serviceAccountTable    statedb.Table[ServiceAccount]
	enrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
}

func NewEnrollmentReconciler(cfg params) reconciler.Operations[*table.EnrolledNamespace] {
	ops := &EnrollmentReconciler{
		logger:                 cfg.Logger,
		spireClient:            cfg.SpireClient,
		db:                     cfg.DB,
		serviceAccountTable:    cfg.ServiceAccountTable,
		enrolledNamespaceTable: cfg.EnrolledNamespaceTable,
	}
	cfg.Lifecycle.Append(ops)
	return ops
}

func (ops *EnrollmentReconciler) Delete(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	// Namespace was enrolled, remove all service accounts in the namespace from the CA.
	sas := ops.serviceAccountTable.List(txn, ServiceAccountNamespaceIndex.Query(ns.Name))
	ids := []string{}
	for sa := range sas {
		ids = append(ids, fmt.Sprintf("%s/%s", sa.Namespace, sa.Name))
	}
	if len(ids) == 0 {
		ops.logger.Info("No service accounts found in deleted enrolled namespace", slog.String("namespace", ns.Name))
		return nil
	}
	err := ops.spireClient.DeleteBatch(ctx, ids)
	if err != nil {
		ops.logger.Error("failed to delete CA entries for deleted enrolled namespace", slog.String("namespace", ns.Name), slog.String("error", err.Error()))
		return err
	}
	ops.logger.Info("Deleted CA entries for deleted enrolled namespace", slog.String("namespace", ns.Name), slog.Int("serviceaccounts", len(ids)))
	return nil
}

// Prune unexpected entries.
func (ops *EnrollmentReconciler) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*table.EnrolledNamespace, statedb.Revision]) error {
	return nil
}

func (ops *EnrollmentReconciler) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	ops.logger.Debug("Reconciling namespace", slog.String("namespace", ns.Name))

	// Namespace is enrolled, nsure all service accounts in the namespace are
	// present in the CA.
	sas := ops.serviceAccountTable.List(txn, ServiceAccountNamespaceIndex.Query(ns.Name))
	entries := []*types.Entry{}
	trustDomain := ops.spireClient.GetSpireTrustDomain()
	spireEntryConfig := ops.spireClient.GetSpireEntryConfig()
	pathFunc := spireEntryConfig.PathFunc
	selectorsFunc := spireEntryConfig.SelectorsFunc
	for sa := range sas {
		id := fmt.Sprintf("%s/%s", sa.Namespace, sa.Name)
		entry := &types.Entry{
			SpiffeId: &types.SPIFFEID{
				TrustDomain: trustDomain,
				Path:        pathFunc(id),
			},
			ParentId: &types.SPIFFEID{
				TrustDomain: trustDomain,
				Path:        spireEntryConfig.ParentID,
			},
			Selectors: selectorsFunc(id),
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		ops.logger.Info("No service accounts found in enrolled namespace", slog.String("namespace", ns.Name))
		return nil
	}
	err := ops.spireClient.InsertBatch(ctx, entries)
	if err != nil {
		ops.logger.Error("failed to upsert CA entries for enrolled namespace", slog.String("namespace", ns.Name), slog.String("error", err.Error()))
		return err
	}
	ops.logger.Info("Upserted CA entries for enrolled namespace", slog.String("namespace", ns.Name), slog.Int("serviceaccounts", len(entries)))
	return nil
}

var _ reconciler.Operations[*table.EnrolledNamespace] = &EnrollmentReconciler{}

func (ops *EnrollmentReconciler) Start(ctx cell.HookContext) error {
	_, initialized := ops.serviceAccountTable.Initialized(ops.db.ReadTxn())
	select {
	case <-ctx.Done():
		ops.logger.Info("Stopping reconciler")
		return nil
	case <-initialized:
	}
	ops.logger.Info("ServiceAccount table initialized")
	_, initialized = ops.enrolledNamespaceTable.Initialized(ops.db.ReadTxn())
	select {
	case <-ctx.Done():
		ops.logger.Info("Stopping reconciler")
		return nil
	case <-initialized:
	}
	ops.logger.Info("EnrolledNamespace table initialized")

	go func() {
		// Start watching for changes in the ServiceAccount table.
		ops.logger.Info("Starting mTLS enrollment reconciler")
		wtxn := ops.db.WriteTxn(ops.serviceAccountTable)
		changeIterator, err := ops.serviceAccountTable.Changes(wtxn)
		wtxn.Commit()
		if err != nil {
			ops.logger.Error("failed to create change iterator", slog.String("error", err.Error()))
			return
		}
		// Wait for SPIRE client to initialize
		<-ops.spireClient.Initialized()
		ops.logger.Info("SPIRE client initialized")

		for {
			changes, watch := changeIterator.Next(ops.db.ReadTxn())
			for change := range changes {
				sa := change.Object
				if change.Deleted {
					ops.logger.Debug("ServiceAccount deleted", slog.String("name", sa.Name))
					id := fmt.Sprintf("%s/%s", sa.Namespace, sa.Name)
					err := ops.spireClient.Delete(context.Background(), id)
					if err != nil {
						ops.logger.Error("failed to delete CA entry", slog.String("error", err.Error()), slog.String("id", id))
					} else {
						ops.logger.Info("CA entry deleted", slog.String("id", id))
					}
				} else {
					ops.logger.Debug("ServiceAccount added/updated", slog.String("name", sa.Name))
					// Check if the service account belongs to an enrolled namespace
					// by query the enrolled namespace table.
					_, _, found := ops.enrolledNamespaceTable.Get(ops.db.ReadTxn(), table.EnrolledNamespacesNameIndex.Query(sa.Namespace))
					if !found {
						ops.logger.Debug("Namespace not enrolled for mTLS", slog.String("namespace", sa.Namespace))
						continue
					}
					// Upsert the CA entry.
					id := fmt.Sprintf("%s/%s", sa.Namespace, sa.Name)
					err := ops.spireClient.Upsert(context.Background(), id)
					if err != nil {
						ops.logger.Error("failed to upsert CA entry", slog.String("error", err.Error()), slog.String("id", id))
					} else {
						ops.logger.Info("CA entry upserted", slog.String("id", id))
					}
				}
			}
			<-watch
		}
	}()
	return nil
}

func (ops *EnrollmentReconciler) Stop(cell.HookContext) error {
	ops.logger.Info("Stopping reconciler")
	return nil
}

var _ cell.HookInterface = &EnrollmentReconciler{}
