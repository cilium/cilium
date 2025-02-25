// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"crypto/sha256"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	k8syaml "sigs.k8s.io/yaml"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	configChecksumAnnotation = "gateway.cilium.io/config-checksum"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *gatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "gatewayclass",
		logfields.Resource, req.NamespacedName,
	)

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

	if ref := gwc.Spec.ParametersRef; ref != nil {
		if !isParameterRefSupported(ref) {
			scopedLog.Error("Only CiliumGatewayClassConfig is supported for ParametersRef")
			setGatewayClassAccepted(gwc, false)
			if err := r.ensureStatus(ctx, gwc, original); err != nil {
				scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
				return controllerruntime.Fail(err)
			}
			return controllerruntime.Fail(nil)
		}

		if ref.Namespace == nil || ref.Name == "" {
			scopedLog.Error("ParametersRef must specify namespace and name")
			setGatewayClassAccepted(gwc, false)
			if err := r.ensureStatus(ctx, gwc, original); err != nil {
				scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
				return controllerruntime.Fail(err)
			}
			return controllerruntime.Fail(nil)
		}

		cgcc := &v2alpha1.CiliumGatewayClassConfig{}
		key := client.ObjectKey{
			Namespace: string(*ref.Namespace),
			Name:      ref.Name,
		}
		if err := r.Client.Get(ctx, key, cgcc); err != nil {
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
		gwc.Annotations[configChecksumAnnotation] = checksum(cgcc)

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

// checksum returns a sha256 checksum of CiliumGatewayClassConfig.spec.
// This is used to detect changes in the referenced CiliumGatewayClassConfig.
func checksum(cfg *v2alpha1.CiliumGatewayClassConfig) string {
	hash := sha256.New()
	b, _ := k8syaml.Marshal(cfg.Spec)
	hash.Write(b)
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func isParameterRefSupported(ref *gatewayv1.ParametersReference) bool {
	if ref == nil {
		return false
	}
	return ref.Group == v2alpha1.CustomResourceDefinitionGroup &&
		ref.Kind == v2alpha1.CGCCKindDefinition
}
