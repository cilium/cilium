// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// controllerName is the gateway controller name used in cilium.
	controllerName = "io.cilium/gateway-controller"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(gatewayv1beta1.AddToScheme(scheme))
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
}

type internalModel struct {
	// TODO(tam): I am not sure if we need to cache anything for performance gain,
	// the client is reading from cache already.
}

type Controller struct {
	mgr ctrl.Manager

	model *internalModel
}

// NewController returns a new gateway controller, which is implemented
// using the controller-runtime library.
func NewController() (*Controller, error) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, err
	}

	m := new(internalModel)

	gwcReconciler := &gatewayClassReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		Model:          m,
		controllerName: controllerName,
	}
	if err = gwcReconciler.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	gwReconciler := &gatewayReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Model:  m,
	}
	if err = gwReconciler.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	hrReconciler := &httpRouteReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Model:  m,
	}
	if err = hrReconciler.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	return &Controller{
		mgr:   mgr,
		model: m,
	}, nil
}

func (m *Controller) Run() {
	if err := m.mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.WithField(logfields.Controller, "gateway-api").WithError(err).Error("Unable to start controller")
	}
}

func success() (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func fail(e error) (ctrl.Result, error) {
	return ctrl.Result{}, e
}
