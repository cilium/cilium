// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotations

import (
	"strconv"

	"github.com/cilium/cilium/pkg/annotation"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
)

const (
	LBModeAnnotation           = annotation.IngressPrefix + "/loadbalancer-mode"
	ServiceTypeAnnotation      = annotation.IngressPrefix + "/service-type"
	InsecureNodePortAnnotation = annotation.IngressPrefix + "/insecure-node-port"
	SecureNodePortAnnotation   = annotation.IngressPrefix + "/secure-node-port"

	TCPKeepAliveEnabledAnnotation          = annotation.IngressPrefix + "/tcp-keep-alive"
	TCPKeepAliveIdleAnnotation             = annotation.IngressPrefix + "/tcp-keep-alive-idle"
	TCPKeepAliveProbeIntervalAnnotation    = annotation.IngressPrefix + "/tcp-keep-alive-probe-interval"
	TCPKeepAliveProbeMaxFailuresAnnotation = annotation.IngressPrefix + "/tcp-keep-alive-probe-max-failures"
	WebsocketEnabledAnnotation             = annotation.IngressPrefix + "/websocket"

	LBModeAnnotationAlias           = annotation.Prefix + ".ingress" + "/loadbalancer-mode"
	ServiceTypeAnnotationAlias      = annotation.Prefix + ".ingress" + "/service-type"
	InsecureNodePortAnnotationAlias = annotation.Prefix + ".ingress" + "/insecure-node-port"
	SecureNodePortAnnotationAlias   = annotation.Prefix + ".ingress" + "/secure-node-port"

	TCPKeepAliveEnabledAnnotationAlias          = annotation.Prefix + "/tcp-keep-alive"
	TCPKeepAliveIdleAnnotationAlias             = annotation.Prefix + "/tcp-keep-alive-idle"
	TCPKeepAliveProbeIntervalAnnotationAlias    = annotation.Prefix + "/tcp-keep-alive-probe-interval"
	TCPKeepAliveProbeMaxFailuresAnnotationAlias = annotation.Prefix + "/tcp-keep-alive-probe-max-failures"
	WebsocketEnabledAnnotationAlias             = annotation.Prefix + "/websocket"
)

const (
	enabled                          = "enabled"
	defaultTCPKeepAliveEnabled       = 1  // 1 - Enabled, 0 - Disabled
	defaultTCPKeepAliveInitialIdle   = 10 // in seconds
	defaultTCPKeepAliveProbeInterval = 5  // in seconds
	defaultTCPKeepAliveMaxProbeCount = 10
	defaultWebsocketEnabled          = 0 // 1 - Enabled, 0 - Disabled
)

// GetAnnotationIngressLoadbalancerMode returns the loadbalancer mode for the ingress if possible.
func GetAnnotationIngressLoadbalancerMode(ingress *slim_networkingv1.Ingress) string {
	value, _ := annotation.Get(ingress, LBModeAnnotation, LBModeAnnotationAlias)
	return value
}

// GetAnnotationServiceType returns the service type for the ingress if possible.
// Defaults to LoadBalancer
func GetAnnotationServiceType(ingress *slim_networkingv1.Ingress) string {
	val, exists := annotation.Get(ingress, ServiceTypeAnnotation, ServiceTypeAnnotationAlias)
	if !exists {
		return string(slim_corev1.ServiceTypeLoadBalancer)
	}
	return val
}

// GetAnnotationSecureNodePort returns the secure node port for the ingress if possible.
func GetAnnotationSecureNodePort(ingress *slim_networkingv1.Ingress) (*uint32, error) {
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
func GetAnnotationInsecureNodePort(ingress *slim_networkingv1.Ingress) (*uint32, error) {
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

// GetAnnotationTCPKeepAliveEnabled returns 1 if enabled (default), 0 if disabled
func GetAnnotationTCPKeepAliveEnabled(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := annotation.Get(ingress, TCPKeepAliveEnabledAnnotation, TCPKeepAliveEnabledAnnotationAlias)
	if !exists {
		return defaultTCPKeepAliveEnabled
	}
	if val == enabled {
		return 1
	}
	return 0
}

// GetAnnotationTCPKeepAliveIdle returns the time (in seconds) the connection needs to
// remain idle before TCP starts sending keepalive probes. Defaults to 10s.
// Related references:
//   - https://man7.org/linux/man-pages/man7/tcp.7.html
func GetAnnotationTCPKeepAliveIdle(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := annotation.Get(ingress, TCPKeepAliveIdleAnnotation, TCPKeepAliveIdleAnnotationAlias)
	if !exists {
		return defaultTCPKeepAliveInitialIdle
	}
	intVal, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return defaultTCPKeepAliveInitialIdle
	}
	return intVal
}

// GetAnnotationTCPKeepAliveProbeInterval returns the time (in seconds) between individual
// keepalive probes. Defaults to 5s.
// Related references:
//   - https://man7.org/linux/man-pages/man7/tcp.7.html
func GetAnnotationTCPKeepAliveProbeInterval(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := annotation.Get(ingress, TCPKeepAliveProbeIntervalAnnotation, TCPKeepAliveProbeIntervalAnnotationAlias)
	if !exists {
		return defaultTCPKeepAliveProbeInterval
	}
	intVal, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return defaultTCPKeepAliveProbeInterval
	}
	return intVal
}

// GetAnnotationTCPKeepAliveProbeMaxFailures returns the maximum number of keepalive probes TCP
// should send before dropping the connection. Defaults to 10.
// Related references:
//   - https://man7.org/linux/man-pages/man7/tcp.7.html
func GetAnnotationTCPKeepAliveProbeMaxFailures(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := annotation.Get(ingress, TCPKeepAliveProbeMaxFailuresAnnotation, TCPKeepAliveProbeMaxFailuresAnnotationAlias)
	if !exists {
		return defaultTCPKeepAliveMaxProbeCount
	}
	intVal, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return defaultTCPKeepAliveMaxProbeCount
	}
	return intVal
}

// GetAnnotationWebsocketEnabled returns 1 if enabled (default), 0 if disabled
func GetAnnotationWebsocketEnabled(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := annotation.Get(ingress, WebsocketEnabledAnnotation, WebsocketEnabledAnnotationAlias)
	if !exists {
		return defaultWebsocketEnabled
	}
	if val == enabled {
		return 1
	}
	return 0
}
