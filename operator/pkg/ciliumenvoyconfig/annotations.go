// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
)

const (
	servicePrefixAnnotation = annotation.Prefix + ".service"
	lbEnabledAnnotation     = servicePrefixAnnotation + "/lb-l7"
	lbModeAnnotation        = servicePrefixAnnotation + "/lb-l7-algorithm"
)

// IsLBProtocolAnnotationEnabled returns true if the load balancer protocol is enabled
func IsLBProtocolAnnotationEnabled(obj metav1.Object) bool {
	return obj.GetAnnotations()[lbEnabledAnnotation] == "enabled"
}

// GetLBProtocolModelAnnotation returns the load balancer mode
func GetLBProtocolModelAnnotation(obj metav1.Object) string {
	return obj.GetAnnotations()[lbModeAnnotation]
}
