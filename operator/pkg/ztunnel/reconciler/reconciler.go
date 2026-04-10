// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"iter"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/operator/auth/spire"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

// requeueNamespace marks an enrolled namespace as pending so the reconciler
// will re-reconcile it on transient SPIRE failures.
func requeueNamespace(db *statedb.DB, enrolledTbl statedb.RWTable[*table.EnrolledNamespace], namespace string) {
	txn := db.WriteTxn(enrolledTbl)
	ns, _, found := enrolledTbl.Get(txn, table.EnrolledNamespacesNameIndex.Query(namespace))
	if found {
		clone := ns.Clone()
		clone.Status = reconciler.StatusPending()
		enrolledTbl.Insert(txn, clone)
	}
	txn.Commit()
}

// SpireClient is the interface for interacting with SPIRE for enrollment purposes.
type SpireClient interface {
	UpsertBatch(ctx context.Context, ids []string) error
	DeleteBatch(ctx context.Context, ids []string) error
	Upsert(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
	Initialized() <-chan struct{}
}

type params struct {
	cell.In

	DB                     *statedb.DB
	ServiceAccountTable    statedb.Table[ServiceAccount]
	EnrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
	SpireClient            *spire.Client
	Logger                 *slog.Logger
	Lifecycle              cell.Lifecycle
	Metrics                *Metrics
}

type EnrollmentReconciler struct {
	db                     *statedb.DB
	logger                 *slog.Logger
	spireClient            SpireClient
	serviceAccountTable    statedb.Table[ServiceAccount]
	enrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
	metrics                *Metrics
	cancel                 context.CancelFunc
}

func NewEnrollmentReconciler(cfg params) reconciler.Operations[*table.EnrolledNamespace] {
	ops := &EnrollmentReconciler{
		logger:                 cfg.Logger,
		spireClient:            cfg.SpireClient,
		db:                     cfg.DB,
		serviceAccountTable:    cfg.ServiceAccountTable,
		enrolledNamespaceTable: cfg.EnrolledNamespaceTable,
		metrics:                cfg.Metrics,
	}
	if cfg.SpireClient != nil {
		cfg.Lifecycle.Append(ops)
	}
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
		ops.logger.Info("No service accounts found in deleted enrolled namespace", logfields.K8sNamespace, ns.Name)
		return nil
	}
	err := ops.spireClient.DeleteBatch(ctx, ids)
	if err != nil {
		ops.logger.Error("failed to delete CA entries for deleted enrolled namespace",
			logfields.K8sNamespace, ns.Name,
			logfields.Error, err.Error())
		ops.metrics.EnrollmentOps.WithLabelValues(LabelValueMethodDelete, LabelValueOutcomeFail).Add(float64(len(ids)))
		return err
	}
	ops.logger.Info("Deleted CA entries for deleted enrolled namespace",
		logfields.K8sNamespace, ns.Name,
		logfields.Count, len(ids))
	ops.metrics.EnrollmentOps.WithLabelValues(LabelValueMethodDelete, LabelValueOutcomeSuccess).Add(float64(len(ids)))
	return nil
}

// Prune unexpected entries.
func (ops *EnrollmentReconciler) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*table.EnrolledNamespace, statedb.Revision]) error {
	return nil
}

func (ops *EnrollmentReconciler) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	ops.logger.Debug("Reconciling namespace", logfields.K8sNamespace, ns.Name)

	// Namespace is enrolled, ensure all service accounts in the namespace are
	// present in the CA.
	sas := ops.serviceAccountTable.List(txn, ServiceAccountNamespaceIndex.Query(ns.Name))
	var ids []string
	for sa := range sas {
		ids = append(ids, fmt.Sprintf("%s/%s", sa.Namespace, sa.Name))
	}
	if len(ids) == 0 {
		ops.logger.Info("No service accounts found in enrolled namespace", logfields.K8sNamespace, ns.Name)
		return nil
	}
	err := ops.spireClient.UpsertBatch(ctx, ids)
	if err != nil {
		ops.logger.Error("failed to upsert CA entries for enrolled namespace",
			logfields.K8sNamespace, ns.Name,
			logfields.Error, err.Error())
		ops.metrics.EnrollmentOps.WithLabelValues(LabelValueMethodUpsert, LabelValueOutcomeFail).Add(float64(len(ids)))
		return err
	}
	ops.logger.Info("Upserted CA entries for enrolled namespace",
		logfields.K8sNamespace, ns.Name,
		logfields.Count, len(ids))
	ops.metrics.EnrollmentOps.WithLabelValues(LabelValueMethodUpsert, LabelValueOutcomeSuccess).Add(float64(len(ids)))
	return nil
}

var _ reconciler.Operations[*table.EnrolledNamespace] = &EnrollmentReconciler{}

func (ops *EnrollmentReconciler) Start(cell.HookContext) error {
	ctx, cancel := context.WithCancel(context.Background())
	ops.cancel = cancel

	go func() {
		ops.logger.Info("Starting mTLS enrollment reconciler")

		// Wait for tables to initialize before processing changes.
		_, saInit := ops.serviceAccountTable.Initialized(ops.db.ReadTxn())
		select {
		case <-ctx.Done():
			return
		case <-saInit:
		}
		ops.logger.Info("ServiceAccount table initialized")

		_, nsInit := ops.enrolledNamespaceTable.Initialized(ops.db.ReadTxn())
		select {
		case <-ctx.Done():
			return
		case <-nsInit:
		}
		ops.logger.Info("EnrolledNamespace table initialized")

		wtxn := ops.db.WriteTxn(ops.serviceAccountTable)
		changeIterator, err := ops.serviceAccountTable.Changes(wtxn)
		wtxn.Commit()
		if err != nil {
			ops.logger.Error("failed to create change iterator", logfields.Error, err.Error())
			return
		}

		// Wait for SPIRE client to initialize.
		select {
		case <-ctx.Done():
			return
		case <-ops.spireClient.Initialized():
		}
		ops.logger.Info("SPIRE client initialized")

		for {
			changes, watch := changeIterator.Next(ops.db.ReadTxn())
			for change := range changes {
				sa := change.Object
				id := fmt.Sprintf("%s/%s", sa.Namespace, sa.Name)
				if change.Deleted {
					ops.logger.Debug("ServiceAccount deleted", logfields.Name, sa.Name)
					if err := ops.spireClient.Delete(ctx, id); err != nil {
						ops.logger.Error("failed to delete CA entry",
							logfields.Error, err.Error(),
							logfields.Identity, id)
						ops.metrics.EnrollmentOps.WithLabelValues(LabelValueMethodDelete, LabelValueOutcomeFail).Inc()
						requeueNamespace(ops.db, ops.enrolledNamespaceTable, sa.Namespace)
					} else {
						ops.logger.Info("CA entry deleted", logfields.Identity, id)
						ops.metrics.EnrollmentOps.WithLabelValues(LabelValueMethodDelete, LabelValueOutcomeSuccess).Inc()
					}
				} else {
					ops.logger.Debug("ServiceAccount added/updated", logfields.Name, sa.Name)
					_, _, found := ops.enrolledNamespaceTable.Get(ops.db.ReadTxn(), table.EnrolledNamespacesNameIndex.Query(sa.Namespace))
					if !found {
						ops.logger.Debug("Namespace not enrolled for mTLS", logfields.K8sNamespace, sa.Namespace)
						continue
					}
					if err := ops.spireClient.Upsert(ctx, id); err != nil {
						ops.logger.Error("failed to upsert CA entry",
							logfields.Error, err.Error(),
							logfields.Identity, id)
						ops.metrics.EnrollmentOps.WithLabelValues(LabelValueMethodUpsert, LabelValueOutcomeFail).Inc()
						requeueNamespace(ops.db, ops.enrolledNamespaceTable, sa.Namespace)
					} else {
						ops.logger.Info("CA entry upserted", logfields.Identity, id)
						ops.metrics.EnrollmentOps.WithLabelValues(LabelValueMethodUpsert, LabelValueOutcomeSuccess).Inc()
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-watch:
			}
		}
	}()
	return nil
}

func (ops *EnrollmentReconciler) Stop(cell.HookContext) error {
	if ops.cancel != nil {
		ops.cancel()
	}
	ops.logger.Info("Stopping reconciler")
	return nil
}

var _ cell.HookInterface = &EnrollmentReconciler{}
