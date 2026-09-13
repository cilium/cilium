// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

// AnnotationsEqual returns whether the annotation with any key in
// relevantAnnotations is equal in anno1 and anno2.
func AnnotationsEqual(relevantAnnotations []string, anno1, anno2 map[string]string) bool {
	for _, an := range relevantAnnotations {
		if anno1[an] != anno2[an] {
			return false
		}
	}
	return true
}

// TransformToCiliumEndpoint transforms a *cilium_v2.CiliumEndpoint into a
// *types.CiliumEndpoint, dropping the fields which are not used by the CEP
// handlers.
//
// The deletions which the informer reports as cache.DeletedFinalStateUnknown
// tombstones never reach the transform, so there is nothing to unwrap here:
// see resource.WithTransform.
func TransformToCiliumEndpoint(cep *cilium_v2.CiliumEndpoint) (*types.CiliumEndpoint, error) {
	return &types.CiliumEndpoint{
		TypeMeta: slim_metav1.TypeMeta{
			Kind:       cep.TypeMeta.Kind,
			APIVersion: cep.TypeMeta.APIVersion,
		},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            cep.ObjectMeta.Name,
			Namespace:       cep.ObjectMeta.Namespace,
			UID:             cep.ObjectMeta.UID,
			ResourceVersion: cep.ObjectMeta.ResourceVersion,
			// We don't need to store labels nor annotations because
			// they are not used by the CEP handlers.
			Labels:      nil,
			Annotations: nil,
			// OwnerReferences is needed for ztunnel xDS to extract Pod UID.
			OwnerReferences: slim_metav1.SlimOwnerReferences(cep.ObjectMeta.OwnerReferences),
		},
		// Copied rather than pointed at: &cep.Status.Encryption would keep the
		// whole decoded endpoint alive, which is what the transform is here to
		// avoid. See resource.WithTransform.
		Encryption: func() *cilium_v2.EncryptionSpec {
			enc := cep.Status.Encryption
			return &enc
		}(),
		Identity:       cep.Status.Identity,
		Networking:     cep.Status.Networking,
		NamedPorts:     cep.Status.NamedPorts,
		ServiceAccount: cep.Status.ServiceAccount,
	}, nil
}

// ConvertCEPToCoreCEP converts a CiliumEndpoint to a CoreCiliumEndpoint
// containing only a minimal set of entities used to
func ConvertCEPToCoreCEP(cep *cilium_v2.CiliumEndpoint) *cilium_v2alpha1.CoreCiliumEndpoint {
	// Copy Networking field into core CEP
	var epNetworking *cilium_v2.EndpointNetworking
	if cep.Status.Networking != nil {
		epNetworking = new(cilium_v2.EndpointNetworking)
		cep.Status.Networking.DeepCopyInto(epNetworking)
	}
	var identityID int64 = 0
	if cep.Status.Identity != nil {
		identityID = cep.Status.Identity.ID
	}
	return &cilium_v2alpha1.CoreCiliumEndpoint{
		Name:           cep.GetName(),
		IdentityID:     identityID,
		PodUID:         getPodUIDFromOwnerRefs(cep.OwnerReferences),
		Networking:     epNetworking,
		Encryption:     cep.Status.Encryption,
		NamedPorts:     cep.Status.NamedPorts.DeepCopy(),
		ServiceAccount: cep.Status.ServiceAccount,
	}
}

// getPodUIDFromOwnerRefs extracts the Pod UID from a list of OwnerReferences.
func getPodUIDFromOwnerRefs(refs []metav1.OwnerReference) string {
	for _, ref := range refs {
		if ref.Kind == "Pod" {
			return string(ref.UID)
		}
	}
	return ""
}

// ConvertCoreCiliumEndpointToTypesCiliumEndpoint converts CoreCiliumEndpoint object to types.CiliumEndpoint.
func ConvertCoreCiliumEndpointToTypesCiliumEndpoint(ccep *cilium_v2alpha1.CoreCiliumEndpoint, ns string) *types.CiliumEndpoint {
	var ownerRefs []slim_metav1.OwnerReference
	if ccep.PodUID != "" {
		ownerRefs = []slim_metav1.OwnerReference{
			{
				Kind: "Pod",
				UID:  k8sTypes.UID(ccep.PodUID),
			},
		}
	}

	return &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            ccep.Name,
			Namespace:       ns,
			OwnerReferences: ownerRefs,
		},
		Encryption: func() *cilium_v2.EncryptionSpec {
			enc := ccep.Encryption
			return &enc
		}(),
		Identity: &cilium_v2.EndpointIdentity{
			ID: ccep.IdentityID,
		},
		Networking:     ccep.Networking,
		NamedPorts:     ccep.NamedPorts,
		ServiceAccount: ccep.ServiceAccount,
	}
}
