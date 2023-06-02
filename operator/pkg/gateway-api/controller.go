// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
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
	utilruntime.Must(gatewayv1alpha2.AddToScheme(scheme))
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
func NewController(enableSecretSync bool, secretsNamespace string, idleTimeoutSeconds int) (*Controller, error) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		// Disable controller metrics server in favour of cilium's metrics server.
		MetricsBindAddress: "0",
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
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		SecretsNamespace:   secretsNamespace,
		Model:              m,
		controllerName:     controllerName,
		IdleTimeoutSeconds: idleTimeoutSeconds,
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

	tlsReconciler := &tlsRouteReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Model:  m,
	}
	if err = tlsReconciler.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	rgReconciler := &referenceGrantReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Model:  m,
	}
	if err = rgReconciler.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	if enableSecretSync {
		secretReconciler := &secretSyncer{
			Client:           mgr.GetClient(),
			Scheme:           mgr.GetScheme(),
			SecretsNamespace: secretsNamespace,
			controllerName:   controllerName,
		}
		if err = secretReconciler.SetupWithManager(mgr); err != nil {
			return nil, err
		}
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

func hasMatchingController(ctx context.Context, c client.Client, controllerName string) func(object client.Object) bool {
	return func(obj client.Object) bool {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: gateway,
			logfields.Resource:   obj.GetName(),
		})
		gw, ok := obj.(*gatewayv1beta1.Gateway)
		if !ok {
			return false
		}

		gwc := &gatewayv1beta1.GatewayClass{}
		key := types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}
		if err := c.Get(ctx, key, gwc); err != nil {
			scopedLog.WithError(err).Error("Unable to get GatewayClass")
			return false
		}

		return string(gwc.Spec.ControllerName) == controllerName
	}
}

func getGatewaysForSecret(ctx context.Context, c client.Client, obj client.Object) []types.NamespacedName {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.Controller: gateway,
		logfields.Resource:   obj.GetName(),
	})

	gwList := &gatewayv1beta1.GatewayList{}
	if err := c.List(ctx, gwList); err != nil {
		scopedLog.WithError(err).Warn("Unable to list Gateways")
		return nil
	}

	var gateways []types.NamespacedName
	for _, gw := range gwList.Items {
		for _, l := range gw.Spec.Listeners {
			if l.TLS == nil {
				continue
			}

			for _, cert := range l.TLS.CertificateRefs {
				if !IsSecret(cert) {
					continue
				}
				ns := namespaceDerefOr(cert.Namespace, gw.GetNamespace())
				if string(cert.Name) == obj.GetName() &&
					ns == obj.GetNamespace() {
					gateways = append(gateways, client.ObjectKey{
						Namespace: ns,
						Name:      gw.GetName(),
					})
				}
			}
		}
	}
	return gateways
}

func getGatewaysForNamespace(ctx context.Context, c client.Client, ns client.Object) []types.NamespacedName {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.Controller:   gateway,
		logfields.K8sNamespace: ns.GetName(),
	})

	gwList := &gatewayv1beta1.GatewayList{}
	if err := c.List(ctx, gwList); err != nil {
		scopedLog.WithError(err).Warn("Unable to list Gateways")
		return nil
	}

	var gateways []types.NamespacedName
	for _, gw := range gwList.Items {
		for _, l := range gw.Spec.Listeners {
			if l.AllowedRoutes == nil || l.AllowedRoutes.Namespaces == nil {
				continue
			}

			switch *l.AllowedRoutes.Namespaces.From {
			case gatewayv1beta1.NamespacesFromAll:
				gateways = append(gateways, client.ObjectKey{
					Namespace: gw.GetNamespace(),
					Name:      gw.GetName(),
				})
			case gatewayv1beta1.NamespacesFromSame:
				if ns.GetName() == gw.GetNamespace() {
					gateways = append(gateways, client.ObjectKey{
						Namespace: gw.GetNamespace(),
						Name:      gw.GetName(),
					})
				}
			case gatewayv1beta1.NamespacesFromSelector:
				nsList := &corev1.NamespaceList{}
				err := c.List(ctx, nsList, client.MatchingLabels(l.AllowedRoutes.Namespaces.Selector.MatchLabels))
				if err != nil {
					scopedLog.WithError(err).Warn("Unable to list Namespaces")
					return nil
				}
				for _, item := range nsList.Items {
					if item.GetName() == ns.GetName() {
						gateways = append(gateways, client.ObjectKey{
							Namespace: gw.GetNamespace(),
							Name:      gw.GetName(),
						})
					}
				}
			}
		}
	}
	return gateways
}

// onlyStatusChanged returns true if and only if there is status change for underlying objects.
// Supported objects are GatewayClass, Gateway, and HTTPRoute.
func onlyStatusChanged() predicate.Predicate {
	option := cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			switch e.ObjectOld.(type) {
			case *gatewayv1beta1.GatewayClass:
				o, _ := e.ObjectOld.(*gatewayv1beta1.GatewayClass)
				n, ok := e.ObjectNew.(*gatewayv1beta1.GatewayClass)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			case *gatewayv1beta1.Gateway:
				o, _ := e.ObjectOld.(*gatewayv1beta1.Gateway)
				n, ok := e.ObjectNew.(*gatewayv1beta1.Gateway)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			case *gatewayv1beta1.HTTPRoute:
				o, _ := e.ObjectOld.(*gatewayv1beta1.HTTPRoute)
				n, ok := e.ObjectNew.(*gatewayv1beta1.HTTPRoute)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			case *gatewayv1alpha2.TLSRoute:
				o, _ := e.ObjectOld.(*gatewayv1alpha2.TLSRoute)
				n, ok := e.ObjectNew.(*gatewayv1alpha2.TLSRoute)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			default:
				return false
			}
		},
	}
}

func success() (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func fail(e error) (ctrl.Result, error) {
	return ctrl.Result{}, e
}
