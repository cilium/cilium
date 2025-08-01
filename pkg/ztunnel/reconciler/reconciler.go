// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"strings"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/ztunnel/table"
	"github.com/cilium/cilium/pkg/ztunnel/zds"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

type params struct {
	cell.In

	DB                     *statedb.DB
	EnrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
	Logger                 *slog.Logger
	Lifecycle              cell.Lifecycle
	EndpointManager        endpointmanager.EndpointManager
	EndpointEnroller       zds.EndpointEnroller
	RestorerPromise        promise.Promise[endpointstate.Restorer]
}

type EnrollmentReconciler struct {
	db                     *statedb.DB
	logger                 *slog.Logger
	enrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
	endpointManager        endpointmanager.EndpointManager
	endpointEnroller       zds.EndpointEnroller
	restorerPromise        promise.Promise[endpointstate.Restorer]
	initialized            chan struct{}
}

func NewEnrollmentReconciler(cfg params) reconciler.Operations[*table.EnrolledNamespace] {
	ops := &EnrollmentReconciler{
		logger:                 cfg.Logger,
		db:                     cfg.DB,
		enrolledNamespaceTable: cfg.EnrolledNamespaceTable,
		endpointManager:        cfg.EndpointManager,
		endpointEnroller:       cfg.EndpointEnroller,
		restorerPromise:        cfg.RestorerPromise,
		initialized:            make(chan struct{}),
	}
	cfg.Lifecycle.Append(ops)
	return ops
}

func (ops *EnrollmentReconciler) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	<-ops.initialized
	// Enroll all endpoints in this namespace
	endpoints := ops.endpointManager.GetEndpointsByNamespace(ns.Name)
	for _, ep := range endpoints {
		if ep.GetContainerNetnsPath() == "" || strings.Contains(ep.K8sPodName, "ztunnel") {
			continue
		}
		err := ops.endpointEnroller.EnrollEndpoint(ep)
		if err != nil {
			ops.logger.Error("Failed to enroll endpoint to ztunnel",
				logfields.K8sNamespace, ns.Name,
				logfields.Pod, ep.K8sPodName,
				logfields.Error, err,
			)
			return err
		}
	}
	ops.logger.Info("Enrolled all endpoints in namespace", logfields.K8sNamespace, ns.Name)
	return nil
}

func (ops *EnrollmentReconciler) Delete(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	<-ops.initialized
	// Disenroll all endpoints in this namespace
	endpoints := ops.endpointManager.GetEndpointsByNamespace(ns.Name)
	for _, ep := range endpoints {
		if ep.GetContainerNetnsPath() == "" || strings.Contains(ep.K8sPodName, "ztunnel") {
			continue
		}
		err := ops.endpointEnroller.DisenrollEndpoint(ep)
		if err != nil {
			ops.logger.Error("Failed to disenroll endpoint from ztunnel",
				logfields.K8sNamespace, ns.Name,
				logfields.Pod, ep.K8sPodName,
				logfields.Error, err,
			)
			return err
		}
	}
	ops.logger.Info("Disenrolled all endpoints in namespace",
		logfields.K8sNamespace, ns.Name,
	)
	return nil
}

// Prune unexpected entries.
func (ops *EnrollmentReconciler) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*table.EnrolledNamespace, statedb.Revision]) error {
	return nil
}

var _ reconciler.Operations[*table.EnrolledNamespace] = &EnrollmentReconciler{}

func (ops *EnrollmentReconciler) Start(ctx cell.HookContext) error {
	_, initialized := ops.enrolledNamespaceTable.Initialized(ops.db.ReadTxn())
	select {
	case <-ctx.Done():
		ops.logger.Info("Stopping reconciler")
		return nil
	case <-initialized:
	}
	ops.logger.Info("EnrolledNamespace table initialized")

	restorer, err := ops.restorerPromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to await restorer: %w", err)
	}
	// Wait for endpoint restore to complete before getting endpoints.
	// This is to ensure that we don't miss any endpoints that are restored from disk.
	if err := restorer.WaitForEndpointRestore(ctx); err != nil {
		return fmt.Errorf("failed to wait for endpoint restore: %w", err)
	}

	ops.endpointManager.Subscribe(ops)
	// Get endpoints for initial snapshot
	endpoints := ops.endpointManager.GetEndpoints()
	endpointsToEnroll := make([]*endpoint.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		epNamespace := ep.GetK8sNamespace()
		// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
		if epNamespace == "" || ep.GetContainerNetnsPath() == "" || strings.Contains(ep.K8sPodName, "ztunnel") {
			continue
		}
		// Check if namespace is enrolled
		txn := ops.db.ReadTxn()
		_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespacesNameIndex.Query(epNamespace))
		if !found {
			ops.logger.Info("Skipping enrollment of endpoint in unenrolled namespace",
				logfields.K8sNamespace, epNamespace,
				logfields.Pod, ep.K8sPodName,
			)
			continue
		}
		endpointsToEnroll = append(endpointsToEnroll, ep)
	}
	err = ops.endpointEnroller.InitialSnapshot(endpointsToEnroll...)
	if err != nil {
		ops.logger.Error("Failed to send initial snapshot to ztunnel", logfields.Error, err)
		return err
	}
	ops.logger.Info("Enrollment reconciler initialized")
	close(ops.initialized)
	return nil
}

func (ops *EnrollmentReconciler) Stop(cell.HookContext) error {
	<-ops.initialized
	ops.endpointManager.Unsubscribe(ops)
	ops.logger.Info("Stopping reconciler")
	return nil
}

func (ops *EnrollmentReconciler) EndpointCreated(ep *endpoint.Endpoint) {
	<-ops.initialized
	epNamespace := ep.GetK8sNamespace()
	// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
	if epNamespace == "" || ep.GetContainerNetnsPath() == "" || strings.Contains(ep.K8sPodName, "ztunnel") {
		return
	}
	// Check if namespace is enrolled
	txn := ops.db.ReadTxn()
	_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespacesNameIndex.Query(epNamespace))
	if !found {
		ops.logger.Info("Skipping enrollment of endpoint in unenrolled namespace",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
		)
		return
	}
	err := ops.endpointEnroller.EnrollEndpoint(ep)
	if err != nil {
		ops.logger.Error("Failed to enroll endpoint to ztunnel",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
			logfields.Error, err,
		)
	}
}

func (ops *EnrollmentReconciler) EndpointDeleted(ep *endpoint.Endpoint, _ endpoint.DeleteConfig) {
	epNamespace := ep.GetK8sNamespace()
	// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
	if epNamespace == "" || ep.GetContainerNetnsPath() == "" || strings.Contains(ep.K8sPodName, "ztunnel") {
		return
	}
	// Check if namespace is enrolled
	txn := ops.db.ReadTxn()
	_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespacesNameIndex.Query(epNamespace))
	if !found {
		ops.logger.Info("Skipping disenrollment of endpoint in unenrolled namespace",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
		)
		return
	}
	err := ops.endpointEnroller.DisenrollEndpoint(ep)
	if err != nil {
		ops.logger.Error("Failed to disenroll endpoint from ztunnel",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
			logfields.Error, err,
		)
	}
}

func (ops *EnrollmentReconciler) EndpointRestored(ep *endpoint.Endpoint) {}

var _ cell.HookInterface = &EnrollmentReconciler{}
var _ endpointmanager.Subscriber = &EnrollmentReconciler{}
