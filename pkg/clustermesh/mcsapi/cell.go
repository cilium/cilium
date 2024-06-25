// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	mcsapicontrollers "sigs.k8s.io/mcs-api/pkg/controllers"

	"github.com/cilium/cilium/pkg/clustermesh/operator"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

var Cell = cell.Module(
	"mcsapi",
	"Multi-Cluster Services API",
	cell.Invoke(initMCSAPIController),
)

type mcsAPIParams struct {
	cell.In

	ClusterMesh operator.ClusterMesh
	Cfg         operator.ClusterMeshConfig
	CfgMCSAPI   operator.MCSAPIConfig

	// ClusterInfo is the id/name of the local cluster.
	ClusterInfo types.ClusterInfo

	Clientset          k8sClient.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	Logger logrus.FieldLogger
}

var requiredGVK = []schema.GroupVersionKind{
	mcsapiv1alpha1.SchemeGroupVersion.WithKind("serviceimports"),
	mcsapiv1alpha1.SchemeGroupVersion.WithKind("serviceexports"),
}

func checkCRD(ctx context.Context, clientset k8sClient.Clientset, gvk schema.GroupVersionKind) error {
	if !clientset.IsEnabled() {
		return nil
	}

	crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, gvk.GroupKind().String(), metav1.GetOptions{})
	if err != nil {
		return err
	}

	found := false
	for _, v := range crd.Spec.Versions {
		if v.Name == gvk.Version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("CRD %q does not have version %q", gvk.GroupKind().String(), gvk.Version)
	}

	return nil
}

func checkRequiredCRDs(ctx context.Context, clientset k8sClient.Clientset) error {
	var res error
	for _, gvk := range requiredGVK {
		if err := checkCRD(ctx, clientset, gvk); err != nil {
			res = errors.Join(res, err)
		}
	}
	return res
}

func initMCSAPIController(params mcsAPIParams) error {
	if !params.Clientset.IsEnabled() || params.ClusterMesh != nil || !params.CfgMCSAPI.ClusterMeshEnableMCSAPI {
		return nil
	}

	params.Logger.WithField("requiredGVK", requiredGVK).Info("Checking for required MCS-API resources")
	if err := checkRequiredCRDs(context.Background(), params.Clientset); err != nil {
		params.Logger.WithError(err).Error("Required MCS-API resources are not found, please refer to docs for installation instructions")
		return err
	}
	if err := mcsapiv1alpha1.AddToScheme(params.Scheme); err != nil {
		return err
	}

	if err := newMCSAPIServiceReconciler(params.CtrlRuntimeManager, params.Logger, params.ClusterInfo.Name).SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("Failed to register MCSAPIServiceReconciler: %w", err)
	}

	// Upstream controller that we use as is to update the ServiceImport
	// objects with the IPs of the derived Services.
	svcReconciler := mcsapicontrollers.ServiceReconciler{
		Client: params.CtrlRuntimeManager.GetClient(),
		Log:    params.CtrlRuntimeManager.GetLogger(),
	}
	if err := svcReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("Failed to register mcsapicontrollers.ServiceReconciler: %w", err)
	}

	params.Logger.Info("Multi-Cluster Services API support enabled")
	return nil
}
