package ciliumenvoyconfig

import (
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s"
)

func useL7Identity(m *metav1.ObjectMeta) uint32 {
	if m.GetLabels() != nil {
		if v, ok := m.GetLabels()[k8s.UseL7Identity]; ok {
			if boolValue, err := strconv.ParseUint(v, 10, 32); err == nil {
				return uint32(boolValue)
			}
		}
	}
	return 0
}

func useL7EndpointIdentity(m *metav1.ObjectMeta) uint32 {
	if m.GetLabels() != nil {
		if v, ok := m.GetLabels()[k8s.UseL7EndpointIdentity]; ok {
			if boolValue, err := strconv.ParseUint(v, 10, 32); err == nil {
				return uint32(boolValue)
			}
		}
	}
	return 0
}
