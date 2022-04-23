// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotations

import (
	"strconv"

	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"

	"github.com/cilium/cilium/pkg/annotation"
)

const (
	TCPKeepAliveEnabledAnnotation          = annotation.Prefix + "/tcp-keep-alive"
	TCPKeepAliveIdleAnnotation             = annotation.Prefix + "/tcp-keep-alive-idle"
	TCPKeepAliveProbeIntervalAnnotation    = annotation.Prefix + "/tcp-keep-alive-probe-interval"
	TCPKeepAliveProbeMaxFailuresAnnotation = annotation.Prefix + "/tcp-keep-alive-probe-max-failures"
)

const (
	enabled                          = "enabled"
	defaultTCPKeepAliveEnabled       = 1  // 1 - Enabled, 0 - Disabled
	defaultTCPKeepAliveInitialIdle   = 10 // in seconds
	defaultTCPKeepAliveProbeInterval = 5  // in seconds
	defaultTCPKeepAliveMaxProbeCount = 10
)

// GetAnnotationTCPKeepAliveEnabled returns 1 if enabled (default), 0 if disable
func GetAnnotationTCPKeepAliveEnabled(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := ingress.GetAnnotations()[TCPKeepAliveEnabledAnnotation]
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
// 	- https://man7.org/linux/man-pages/man7/tcp.7.html
func GetAnnotationTCPKeepAliveIdle(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := ingress.GetAnnotations()[TCPKeepAliveIdleAnnotation]
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
// 	- https://man7.org/linux/man-pages/man7/tcp.7.html
func GetAnnotationTCPKeepAliveProbeInterval(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := ingress.GetAnnotations()[TCPKeepAliveProbeIntervalAnnotation]
	if !exists {
		return defaultTCPKeepAliveProbeInterval
	}
	intVal, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return defaultTCPKeepAliveProbeInterval
	}
	return intVal
}

// GetAnnotationTCPKeepAliveProbeMaxFailures return he maximum number of keepalive probes TCP
// should send before dropping the connection. Defaults to 10.
// Related references:
// 	- https://man7.org/linux/man-pages/man7/tcp.7.html
func GetAnnotationTCPKeepAliveProbeMaxFailures(ingress *slim_networkingv1.Ingress) int64 {
	val, exists := ingress.GetAnnotations()[TCPKeepAliveProbeMaxFailuresAnnotation]
	if !exists {
		return defaultTCPKeepAliveMaxProbeCount
	}
	intVal, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return defaultTCPKeepAliveMaxProbeCount
	}
	return intVal
}
