/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"

	"github.com/go-logr/logr"
	discoveryv1beta1 "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

// EndpointSliceReconciler reconciles a EndpointSlice object
type EndpointSliceReconciler struct {
	client.Client
	Log logr.Logger
}

// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch;update;patch

func shouldIgnoreEndpointSlice(epSlice *discoveryv1beta1.EndpointSlice) bool {
	if epSlice.DeletionTimestamp != nil {
		return true
	}
	if epSlice.Labels[v1alpha1.LabelServiceName] == "" {
		return true
	}
	return false
}

// Reconcile the changes.
func (r *EndpointSliceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("endpointslice", req.NamespacedName)

	var epSlice discoveryv1beta1.EndpointSlice
	if err := r.Client.Get(ctx, req.NamespacedName, &epSlice); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if shouldIgnoreEndpointSlice(&epSlice) {
		return ctrl.Result{}, nil
	}
	// Ensure the EndpointSlice is labelled to match the ServiceImport's derived
	// Service.
	serviceName := derivedName(types.NamespacedName{Namespace: epSlice.Namespace, Name: epSlice.Labels[v1alpha1.LabelServiceName]})
	if epSlice.Labels[discoveryv1beta1.LabelServiceName] == serviceName {
		return ctrl.Result{}, nil
	}
	epSlice.Labels[discoveryv1beta1.LabelServiceName] = serviceName
	if err := r.Client.Update(ctx, &epSlice); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("added label", discoveryv1beta1.LabelServiceName, serviceName)
	return ctrl.Result{}, nil
}

// SetupWithManager wires up the controller.
func (r *EndpointSliceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&discoveryv1beta1.EndpointSlice{}).Complete(r)
}
