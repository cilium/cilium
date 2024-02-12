// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotations

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/annotation"
)

const (
	LBModeAnnotation           = annotation.IngressPrefix + "/loadbalancer-mode"
	ServiceTypeAnnotation      = annotation.IngressPrefix + "/service-type"
	InsecureNodePortAnnotation = annotation.IngressPrefix + "/insecure-node-port"
	SecureNodePortAnnotation   = annotation.IngressPrefix + "/secure-node-port"
	TLSPtHostPortAnnotation    = annotation.IngressPrefix + "/tls-passthrough-host-port"
	HTTPHostPortAnnotation     = annotation.IngressPrefix + "/http-host-port"
	TLSPassthroughAnnotation   = annotation.IngressPrefix + "/tls-passthrough"
	ForceHTTPSAnnotation       = annotation.IngressPrefix + "/force-https"

	LBModeAnnotationAlias           = annotation.Prefix + ".ingress" + "/loadbalancer-mode"
	ServiceTypeAnnotationAlias      = annotation.Prefix + ".ingress" + "/service-type"
	InsecureNodePortAnnotationAlias = annotation.Prefix + ".ingress" + "/insecure-node-port"
	SecureNodePortAnnotationAlias   = annotation.Prefix + ".ingress" + "/secure-node-port"
	TLSPassthroughAnnotationAlias   = annotation.Prefix + ".ingress" + "/tls-passthrough"
)

const (
	enabled                          = "enabled"
	disabled                         = "disabled"
	defaultTCPKeepAliveEnabled       = 1  // 1 - Enabled, 0 - Disabled
	defaultTCPKeepAliveInitialIdle   = 10 // in seconds
	defaultTCPKeepAliveProbeInterval = 5  // in seconds
	defaultTCPKeepAliveMaxProbeCount = 10
	defaultWebsocketEnabled          = 0 // 1 - Enabled, 0 - Disabled
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

// GetAnnotationServiceType returns the service type for the ingress if possible.
// Defaults to LoadBalancer
func GetAnnotationServiceType(ingress *networkingv1.Ingress) string {
	val, exists := annotation.Get(ingress, ServiceTypeAnnotation, ServiceTypeAnnotationAlias)
	if !exists {
		return string(corev1.ServiceTypeLoadBalancer)
	}
	return val
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

// GetAnnotationHTTPHostPort returns the HTTP host port for the ingress if possible.
func GetAnnotationHTTPHostPort(ingress *networkingv1.Ingress) (*uint32, error) {
	val, exists := annotation.Get(ingress, HTTPHostPortAnnotation)
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

// GetAnnotationTLSHostPort returns the TLS host port for the ingress if possible.
func GetAnnotationTLSHostPort(ingress *networkingv1.Ingress) (*uint32, error) {
	val, exists := annotation.Get(ingress, TLSPtHostPortAnnotation)
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
