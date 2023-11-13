// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (r *ciliumEnvoyConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
		logfields.Controller: "ciliumenvoyconfig",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Starting reconciliation")

	svc := &corev1.Service{}
	if err := r.client.Get(ctx, req.NamespacedName, svc); err != nil {
		if k8serrors.IsNotFound(err) {
			scopedLog.WithError(err).Debug("Unable to get service - either deleted or not yet available")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	scopedLog.Info("Successfully reconciled")
	return ctrl.Result{}, nil
}
