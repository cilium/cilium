// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotations

import (
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/annotation"
)

const (
	LBModeAnnotation                       = annotation.IngressPrefix + "/loadbalancer-mode"
	LBClassAnnotation                      = annotation.IngressPrefix + "/loadbalancer-class"
	ServiceTypeAnnotation                  = annotation.IngressPrefix + "/service-type"
	ServiceExternalTrafficPolicyAnnotation = annotation.IngressPrefix + "/service-external-traffic-policy"
	InsecureNodePortAnnotation             = annotation.IngressPrefix + "/insecure-node-port"
	SecureNodePortAnnotation               = annotation.IngressPrefix + "/secure-node-port"
	HostListenerPortAnnotation             = annotation.IngressPrefix + "/host-listener-port"
	TLSPassthroughAnnotation               = annotation.IngressPrefix + "/tls-passthrough"
	ForceHTTPSAnnotation                   = annotation.IngressPrefix + "/force-https"
	RequestTimeoutAnnotation               = annotation.IngressPrefix + "/request-timeout"

	LBModeAnnotationAlias           = annotation.Prefix + ".ingress" + "/loadbalancer-mode"
	ServiceTypeAnnotationAlias      = annotation.Prefix + ".ingress" + "/service-type"
	InsecureNodePortAnnotationAlias = annotation.Prefix + ".ingress" + "/insecure-node-port"
	SecureNodePortAnnotationAlias   = annotation.Prefix + ".ingress" + "/secure-node-port"
	TLSPassthroughAnnotationAlias   = annotation.Prefix + ".ingress" + "/tls-passthrough"
)

const (
	enabled  = "enabled"
	disabled = "disabled"
)

const (
	LoadbalancerModeDedicated = "dedicated"
	LoadbalancerModeShared    = "shared"
)

// GetAnnotationIngressLoadbalancerMode returns the loadbalancer mode for the ingress if possible.
func GetAnnotationIngressLoadbalancerMode(ingress *networkingv1.Ingress) string {
	value, _ := annotation.Get(ingress, LBModeAnnotation, LBModeAnnotationAlias)
	return value
}

// GetAnnotationLoadBalancerClass returns the loadbalancer class from the ingress if possible.
// Defaults to nil
func GetAnnotationLoadBalancerClass(ingress *networkingv1.Ingress) *string {
	val, exists := annotation.Get(ingress, LBClassAnnotation)
	if !exists {
		return nil
	}
	return &val
}

// GetAnnotationServiceType returns the service type for the ingress if possible.
// Defaults to LoadBalancer
func GetAnnotationServiceType(ingress *networkingv1.Ingress) string {
	val, exists := annotation.Get(ingress, ServiceTypeAnnotation, ServiceTypeAnnotationAlias)
	if !exists {
		return string(corev1.ServiceTypeLoadBalancer)
	}
	return val
}

// GetAnnotationServiceExternalTrafficPolicy returns the service externalTrafficPolicy for the ingress.
func GetAnnotationServiceExternalTrafficPolicy(ingress *networkingv1.Ingress) (string, error) {
	val, exists := annotation.Get(ingress, ServiceExternalTrafficPolicyAnnotation)
	if !exists {
		return string(corev1.ServiceExternalTrafficPolicyCluster), nil
	}

	switch val {
	case string(corev1.ServiceExternalTrafficPolicyCluster), string(corev1.ServiceExternalTrafficPolicyLocal):
		return val, nil
	default:
		return string(corev1.ServiceExternalTrafficPolicyCluster), fmt.Errorf("invalid value for externalTrafficPolicy %q", val)
	}
}

// GetAnnotationRequestTimeout retrieves the RequestTimeout annotation's value.
func GetAnnotationRequestTimeout(ingress *networkingv1.Ingress) (*time.Duration, error) {
	val, exists := annotation.Get(ingress, RequestTimeoutAnnotation)
	if !exists {
		return nil, nil
	}

	d, err := time.ParseDuration(val)
	if err != nil {
		return nil, fmt.Errorf("failed to parse duration %q: %w", val, err)
	}

	return &d, nil
}

// GetAnnotationSecureNodePort returns the secure node port for the ingress if possible.
func GetAnnotationSecureNodePort(ingress *networkingv1.Ingress) (*uint32, error) {
	val, exists := annotation.Get(ingress, SecureNodePortAnnotation, SecureNodePortAnnotationAlias)
	if !exists {
		return nil, nil
	}
	intVal, err := strconv.ParseInt(val, 10, 32)
	if err != nil {
		return nil, err
	}
	res := uint32(intVal)
	return &res, nil
}

// GetAnnotationInsecureNodePort returns the insecure node port for the ingress if possible.
func GetAnnotationInsecureNodePort(ingress *networkingv1.Ingress) (*uint32, error) {
	val, exists := annotation.Get(ingress, InsecureNodePortAnnotation, InsecureNodePortAnnotationAlias)
	if !exists {
		return nil, nil
	}
	intVal, err := strconv.ParseInt(val, 10, 32)
	if err != nil {
		return nil, err
	}
	res := uint32(intVal)
	return &res, nil
}

// GetAnnotationHostListenerPort returns the host listener port for the ingress if possible.
func GetAnnotationHostListenerPort(ingress *networkingv1.Ingress) (*uint32, error) {
	val, exists := annotation.Get(ingress, HostListenerPortAnnotation)
	if !exists {
		return nil, nil
	}
	intVal, err := strconv.ParseInt(val, 10, 32)
	if err != nil {
		return nil, err
	}
	res := uint32(intVal)
	return &res, nil
}

func GetAnnotationTLSPassthroughEnabled(ingress *networkingv1.Ingress) bool {
	val, exists := annotation.Get(ingress, TLSPassthroughAnnotation, TLSPassthroughAnnotationAlias)
	if !exists {
		return false
	}

	if val == enabled {
		return true
	}

	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}

	return boolVal
}

// GetAnnotationEnforceHTTPSEnabled retrieves the EnforceHTTPS annotation's value.
// This uses a string rather than a bool because the empty string means "unset".
// In this case this matters because if the value is unset, it can be overridden
// by the global config option `--enforce-ingress-https`.
//
// If the annotation is set, will override the global config option in all cases.
//
// Note that `enabled`, `disabled` and `true` or `false` style values (as understood by
// strconv.ParseBool() ) will work. The annotation being present but set to any
// other value will result in returning the empty string (as in, the same as if
// unset).
//
// If the annotation is unset, this returns `nil`.
//
// The only valid values are:
// - &true - the annotation is present and set to a truthy value
// - &false - the annovation is present and set to a false value
// - nil - the annotatation is not present
func GetAnnotationForceHTTPSEnabled(ingress *networkingv1.Ingress) *bool {
	val, exists := annotation.Get(ingress, ForceHTTPSAnnotation)
	if !exists {
		return nil
	}

	if val == enabled {
		return model.AddressOf(true)
	}

	if val == disabled {
		return model.AddressOf(false)
	}

	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return nil
	}

	if boolVal {
		return model.AddressOf(true)
	}

	return model.AddressOf(false)
}
