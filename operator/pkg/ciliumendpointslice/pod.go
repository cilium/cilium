// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	//"context"
	"net/netip"

	"github.com/cilium/cilium/api/v1/models"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"

	//"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	//"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
)

// Make CoreCEP from pods.
// ConvertCEPToCoreCEP converts a CiliumEndpoint to a CoreCiliumEndpoint
// containing only a minimal set of entities
func ConvertPodToCoreCEP(pod *slim_corev1.Pod) *cilium_v2alpha1.CoreCiliumEndpoint {
	// Copy Networking field into core CEP
	var epNetworking *cilium_v2.EndpointNetworking
	var addressPairs cilium_v2.AddressPairList
	for _, podIP := range pod.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err != nil {
			// Handle the error, perhaps log it and continue
			continue
		}
		if ip.Is4() {
			addressPairs = append(addressPairs, &cilium_v2.AddressPair{
				IPV4: ip.String(),
				IPV6: "", // Empty string for IPv6 since this is an IPv4 address
			})
		} else if ip.Is6() {
			addressPairs = append(addressPairs, &cilium_v2.AddressPair{
				IPV4: "", // Empty string for IPv4 since this is an IPv6 address
				IPV6: ip.String(),
			})
		}
	}
	//if pod.Status.PodIPs != nil {
	epNetworking = &cilium_v2.EndpointNetworking{Addressing: addressPairs}
	//}
	//var identityID int64 = 0
	//if pod.Status.Identity != nil {
	//	identityID = pod.Status.Identity.ID
	//}
	var ports models.NamedPorts
	for _, container := range pod.Spec.Containers {
		for _, containerPort := range container.Ports {
			ports = append(ports, &models.Port{
				Name:     containerPort.Name,
				Port:     uint16(containerPort.ContainerPort),
				Protocol: string(containerPort.Protocol),
			})
		}
	}
	return &cilium_v2alpha1.CoreCiliumEndpoint{
		Name:       pod.GetName(),
		Networking: epNetworking,
		Encryption: cilium_v2.EncryptionSpec{Key: int(node.GetEndpointEncryptKeyIndex())}, //TODO: Populate from the node object
		//IdentityID: identityID,//from CID controller
		NamedPorts: ports,
	}
}
