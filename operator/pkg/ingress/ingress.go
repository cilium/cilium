// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/operator/pkg/model/translation"
	ingressTranslation "github.com/cilium/cilium/operator/pkg/model/translation/ingress"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	ciliumIngressPrefix    = "cilium-ingress"
	ciliumIngressClassName = "cilium"
)

// ingressReconciler reconciles a Ingress object
type ingressReconciler struct {
	logger logrus.FieldLogger
	client client.Client

	maxRetries              int
	enforcedHTTPS           bool
	useProxyProtocol        bool
	secretsNamespace        string
	lbAnnotationPrefixes    []string
	sharedLBServiceName     string
	ciliumNamespace         string
	defaultLoadbalancerMode string
	defaultSecretNamespace  string
	defaultSecretName       string
	idleTimeoutSeconds      int

	sharedTranslator    translation.Translator
	dedicatedTranslator translation.Translator
}

func newIngressReconciler(
	logger logrus.FieldLogger,
	c client.Client,
	ciliumNamespace string,
	enforceHTTPS bool,
	useProxyProtocol bool,
	secretsNamespace string,
	lbAnnotationPrefixes []string,
	sharedLBServiceName string,
	defaultLoadbalancerMode string,
	defaultSecretNamespace string,
	defaultSecretName string,
	proxyIdleTimeoutSeconds int,
) *ingressReconciler {
	return &ingressReconciler{
		logger: logger,
		client: c,

		sharedTranslator:    ingressTranslation.NewSharedIngressTranslator(sharedLBServiceName, ciliumNamespace, secretsNamespace, enforceHTTPS, useProxyProtocol, proxyIdleTimeoutSeconds),
		dedicatedTranslator: ingressTranslation.NewDedicatedIngressTranslator(secretsNamespace, enforceHTTPS, useProxyProtocol, proxyIdleTimeoutSeconds),

		maxRetries:              10,
		enforcedHTTPS:           enforceHTTPS,
		useProxyProtocol:        useProxyProtocol,
		secretsNamespace:        secretsNamespace,
		lbAnnotationPrefixes:    lbAnnotationPrefixes,
		sharedLBServiceName:     sharedLBServiceName,
		ciliumNamespace:         ciliumNamespace,
		defaultLoadbalancerMode: defaultLoadbalancerMode,
		defaultSecretNamespace:  defaultSecretNamespace,
		defaultSecretName:       defaultSecretName,
		idleTimeoutSeconds:      proxyIdleTimeoutSeconds,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ingressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		// (LoadBalancer) Service resource with OwnerReference to the Ingress with dedicated loadbalancing mode
		Owns(&corev1.Service{}).
		// Endpoints resource with OwnerReference to the Ingress with dedicated loadbalancing mode
		Owns(&corev1.Endpoints{}).
		// CiliumEnvoyConfig resource with OwnerReference to the Ingress with dedicated loadbalancing mode
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		Complete(r)
}
