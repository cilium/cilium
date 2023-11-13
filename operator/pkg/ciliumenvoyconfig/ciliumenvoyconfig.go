// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// ciliumEnvoyConfigReconciler syncs secrets to dedicated namespace.
type ciliumEnvoyConfigReconciler struct {
	client client.Client
	logger logrus.FieldLogger

	algorithm          string
	ports              []string
	maxRetries         int
	idleTimeoutSeconds int
}

func newCiliumEnvoyConfigReconciler(c client.Client, logger logrus.FieldLogger, defaultAlgorithm string, ports []string, maxRetries int, idleTimeoutSeconds int) *ciliumEnvoyConfigReconciler {
	return &ciliumEnvoyConfigReconciler{
		client: c,
		logger: logger,

		algorithm:          defaultAlgorithm,
		ports:              ports,
		maxRetries:         maxRetries,
		idleTimeoutSeconds: idleTimeoutSeconds,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ciliumEnvoyConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		Complete(r)
}
