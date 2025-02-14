// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	configMapChecksumAnnotation = "gateway.cilium.io/configmap-checksum"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *gatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(logfields.Controller, "gatewayclass", logfields.Resource, req.NamespacedName)

	scopedLog.Info("Reconciling GatewayClass")
	original := &gatewayv1.GatewayClass{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(err)
	}

	// Ignore deleted GatewayClass, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if original.GetDeletionTimestamp() != nil {
		return controllerruntime.Success()
	}

	gwc := original.DeepCopy()

	if original.Spec.ParametersRef != nil {
		if original.Spec.ParametersRef.Group != "v1" || original.Spec.ParametersRef.Kind != "ConfigMap" {
			scopedLog.Error("Only ConfigMap is supported for ParametersRef")
			setGatewayClassAccepted(original, false)
			return controllerruntime.Fail(nil)
		}

		if original.Spec.ParametersRef.Namespace == nil || original.Spec.ParametersRef.Name == "" {
			scopedLog.Error("ParametersRef must specify namespace and name")
			setGatewayClassAccepted(original, false)
			return controllerruntime.Fail(nil)
		}

		cm := &corev1.ConfigMap{}
		key := client.ObjectKey{
			Namespace: string(*original.Spec.ParametersRef.Namespace),
			Name:      original.Spec.ParametersRef.Name,
		}
		if err := r.Client.Get(ctx, key, cm); err != nil {
			setGatewayClassAccepted(gwc, false)
			if err := r.ensureStatus(ctx, gwc, original); err != nil {
				scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
				return controllerruntime.Fail(err)
			}
			return controllerruntime.Fail(err)
		}

		if gwc.Annotations == nil {
			gwc.Annotations = make(map[string]string)
		}
		gwc.Annotations[configMapChecksumAnnotation] = checksum(cm)

		if err := r.ensureResource(ctx, gwc, original); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to update GatewayClass", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	setGatewayClassAccepted(gwc, true)
	setGatewayClassSupportedFeatures(gwc)
	if err := r.ensureStatus(ctx, gwc, original); err != nil {
		scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	scopedLog.Info("Successfully reconciled GatewayClass")
	return controllerruntime.Success()
}

func (r *gatewayClassReconciler) ensureStatus(ctx context.Context, gwc *gatewayv1.GatewayClass, original *gatewayv1.GatewayClass) error {
	return r.Client.Status().Patch(ctx, gwc, client.MergeFrom(original))
}

func (r *gatewayClassReconciler) ensureResource(ctx context.Context, gwc *gatewayv1.GatewayClass, original *gatewayv1.GatewayClass) error {
	return r.Client.Patch(ctx, gwc, client.MergeFrom(original))
}

// checksum returns a sha256 checksum of the data and binaryData of a ConfigMap.
// This is used to determine if the ConfigMap has changed via annotation.
// BinaryData is not relevant for the GatewayClass ParametersRef.
func checksum(cm *corev1.ConfigMap) string {
	hash := sha256.New()

	var keys []string
	for key := range cm.Data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		hash.Write([]byte(cm.Data[key]))
	}

	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}
