package ciliumendpoint

import (
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

func HasCEWithIdentity(cepStore resource.Store[*v2.CiliumEndpoint], identity string) bool {
	ces, _ := cepStore.IndexKeys(operatorK8s.CiliumEndpointIndexIdentity, identity)
	return len(ces) != 0
}
