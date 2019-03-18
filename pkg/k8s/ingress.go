// Copyright 2018-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func supportV1beta1(ing *types.Ingress) bool {
	// We only support Single Service Ingress for now which means
	// ing.Spec.Backend needs to be different than nil.
	return ing.Spec.Backend != nil
}

// ParseIngressID parses the service ID from the ingress resource
func ParseIngressID(svc *types.Ingress) ServiceID {
	id := ServiceID{
		Namespace: svc.ObjectMeta.Namespace,
	}

	if svc.Spec.Backend != nil {
		id.Name = svc.Spec.Backend.ServiceName
	}

	return id
}

// ParseIngress parses an ingress resources and returns the Service definition
func ParseIngress(ingress *types.Ingress, host net.IP) (ServiceID, *Service, error) {
	svcID := ParseIngressID(ingress)

	if !supportV1beta1(ingress) {
		return svcID, nil, fmt.Errorf("only Single Service Ingress is supported for now, ignoring Ingress")
	}

	ingressPort := ingress.Spec.Backend.ServicePort.IntValue()
	if ingressPort == 0 {
		return svcID, nil, fmt.Errorf("invalid port number")
	}

	svc := NewService(host, false, nil, nil)
	portName := loadbalancer.FEPortName(ingress.Spec.Backend.ServiceName + "/" + ingress.Spec.Backend.ServicePort.String())
	svc.Ports[portName] = loadbalancer.NewFEPort(loadbalancer.TCP, uint16(ingressPort))

	return svcID, svc, nil
}
