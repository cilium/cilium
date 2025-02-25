// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *referenceGrantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, referenceGrant,
		logfields.Resource, req.NamespacedName,
	)

	// TODO(tam): implement the reconcile logic once ReferenceGrant status is available.
	scopedLog.InfoContext(ctx, "Successfully reconciled ReferenceGrant")
	return controllerruntime.Success()
}
