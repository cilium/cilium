package ciliumidentity

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity/basicallocator"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
)

type reconciler struct {
	logger             logrus.FieldLogger
	clientset          k8sClient.Clientset
	idAllocator        *basicallocator.BasicIDAllocator
	desiredCIDState    *CIDState
	cidUsageInPods     *CIDUsageInPods
	cidUsageInCES      *CIDUsageInCES
	cidDeletionTracker *CIDDeletionTracker
	// Ensures no CID duplicates are created while allocating CIDs in parallel,
	// and avoids race conditions when CIDs are being deleted.
	cidCreateLock lock.RWMutex
	cesEnabled    bool

	nsStore  resource.Store[*slim_corev1.Namespace]
	podStore resource.Store[*slim_corev1.Pod]
	cidStore resource.Store[*cilium_api_v2.CiliumIdentity]
	cepStore resource.Store[*cilium_api_v2.CiliumEndpoint]
	cesStore resource.Store[*v2alpha1.CiliumEndpointSlice]
}
