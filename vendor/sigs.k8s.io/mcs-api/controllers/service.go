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
	"slices"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/mcs-api/pkg/apis/v1beta1"
)

// ServiceReconciler reconciles a Service object
type ServiceReconciler struct {
	client.Client
	Log logr.Logger
}

// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch

func serviceImportOwner(refs []metav1.OwnerReference) string {
	for _, ref := range refs {
		if ref.APIVersion == v1beta1.GroupVersion.String() && ref.Kind == serviceImportKind {
			return ref.Name
		}
	}
	return ""
}

// Reconcile the changes.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("service", req.NamespacedName)
	var service v1.Service
	if err := r.Client.Get(ctx, req.NamespacedName, &service); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if service.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	importName := serviceImportOwner(service.OwnerReferences)
	if importName == "" {
		return ctrl.Result{}, nil
	}
	var svcImport v1beta1.ServiceImport
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: importName}, &svcImport); err != nil {
		return ctrl.Result{}, err
	}

	ipsLen := min(2, len(service.Spec.ClusterIPs))
	desiredIPs := service.Spec.ClusterIPs[:ipsLen]
	if service.Spec.ClusterIP == v1.ClusterIPNone {
		desiredIPs = []string{}
	}
	if slices.Equal(desiredIPs, svcImport.Spec.IPs) {
		return ctrl.Result{}, nil
	}

	svcImport.Spec.IPs = desiredIPs
	if err := r.Client.Update(ctx, &svcImport); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("updated serviceimport ip", "ip", service.Spec.ClusterIP)
	return ctrl.Result{}, nil
}

// SetupWithManager wires up the controller.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&v1.Service{}).Complete(r)
}
