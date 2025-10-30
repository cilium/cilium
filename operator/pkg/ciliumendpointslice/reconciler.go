// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/operator/pkg/ciliumidentity"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type doReconciler interface {
	reconcileCES(cesName CESName) error
}

type endpointGetter interface {
	getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint
}

// reconciler is used to sync the current (i.e. desired) state of the CESs in datastore into current state CESs in the k8s-apiserver.
// The source of truth is in local datastore.
type reconciler struct {
	logger   *slog.Logger
	client   clientset.CiliumV2alpha1Interface
	context  context.Context
	cesStore resource.Store[*cilium_v2a1.CiliumEndpointSlice]
	metrics  *Metrics

	cesManager     Manager
	endpointGetter endpointGetter
}

type defaultReconciler struct {
	reconciler

	manager *defaultManager

	cepStore resource.Store[*cilium_v2.CiliumEndpoint]
}

type slimReconciler struct {
	reconciler

	manager *slimManager

	namespaceStore  resource.Store[*slim_corev1.Namespace]
	cidStore        resource.Store[*cilium_v2.CiliumIdentity]
	podStore        resource.Store[*slim_corev1.Pod]
	ciliumNodeStore resource.Store[*cilium_v2.CiliumNode]

	ipsecEnabled bool
	wgEnabled    bool
}

// newDefaultReconciler creates and initializes a new defaultReconciler.
func newDefaultReconciler(
	ctx context.Context,
	client clientset.CiliumV2alpha1Interface,
	cesMgr *defaultManager,
	logger *slog.Logger,
	ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint],
	ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
	metrics *Metrics,
) *defaultReconciler {
	cepStore, _ := ciliumEndpoint.Store(ctx)
	cesStore, _ := ciliumEndpointSlice.Store(ctx)
	dReconciler := defaultReconciler{
		reconciler: reconciler{
			context:    ctx,
			logger:     logger,
			client:     client,
			cesManager: cesMgr,
			cesStore:   cesStore,
			metrics:    metrics,
		},
		manager:  cesMgr,
		cepStore: cepStore,
	}
	dReconciler.reconciler.endpointGetter = &dReconciler
	return &dReconciler
}

// newSlimReconciler creates and initializes a new slimReconciler.
func newSlimReconciler(
	ctx context.Context,
	client clientset.CiliumV2alpha1Interface,
	cesMgr *slimManager,
	logger *slog.Logger,
	ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
	pod resource.Resource[*slim_corev1.Pod],
	ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity],
	ciliumNode resource.Resource[*cilium_v2.CiliumNode],
	namespace resource.Resource[*slim_corev1.Namespace],
	metrics *Metrics,
	ipsecEnabled bool,
	wgEnabled bool,
) *slimReconciler {
	cesStore, _ := ciliumEndpointSlice.Store(ctx)
	podStore, _ := pod.Store(ctx)
	cidStore, _ := ciliumIdentity.Store(ctx)
	ciliumNodeStore, _ := ciliumNode.Store(ctx)
	namespaceStore, _ := namespace.Store(ctx)
	sReconciler := slimReconciler{
		reconciler: reconciler{
			context:    ctx,
			logger:     logger,
			client:     client,
			cesManager: cesMgr,
			cesStore:   cesStore,
			metrics:    metrics,
		},
		namespaceStore:  namespaceStore,
		cidStore:        cidStore,
		podStore:        podStore,
		ciliumNodeStore: ciliumNodeStore,
		manager:         cesMgr,
		ipsecEnabled:    ipsecEnabled,
		wgEnabled:       wgEnabled,
	}
	sReconciler.reconciler.endpointGetter = &sReconciler
	return &sReconciler
}

func (r *reconciler) reconcileCES(cesName CESName) (err error) {
	desiredCEPsNumber := r.cesManager.getCEPCountInCES(cesName)
	r.metrics.CiliumEndpointSliceDensity.Observe(float64(desiredCEPsNumber))
	// Check the CES exists is in cesStore i.e. in api-server copy of CESs, if exist update or delete the CES.
	cesObj, exists, err := r.cesStore.GetByKey(NewCESKey(cesName.string(), "").key())
	if err != nil {
		return
	}
	if !exists && desiredCEPsNumber > 0 {
		return r.reconcileCESCreate(cesName)
	} else if exists && desiredCEPsNumber > 0 {
		return r.reconcileCESUpdate(cesName, cesObj)
	} else if exists && desiredCEPsNumber == 0 {
		return r.reconcileCESDelete(cesObj)
	} else { // !exist && desiredCEPsNumber == 0 => no op
		return nil
	}
}

// Create a new CES in api-server.
func (r *reconciler) reconcileCESCreate(cesName CESName) (err error) {
	r.logger.DebugContext(r.context, "Reconciling CES Create", logfields.CESName, cesName.string())
	ceps := r.cesManager.getCEPinCES(cesName)
	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPInsert).Observe(float64(len(ceps)))
	newCES := &cilium_v2a1.CiliumEndpointSlice{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointSlice",
			APIVersion: cilium_v2.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: cesName.string(),
		},
		Endpoints: make([]cilium_v2a1.CoreCiliumEndpoint, 0, len(ceps)),
	}

	newCES.Namespace = r.cesManager.getCESNamespace(cesName)

	for _, cepName := range ceps {
		ccep := r.endpointGetter.getCoreEndpointFromStore(cepName)
		r.logger.DebugContext(r.context,
			fmt.Sprintf("Adding CEP to new CES (exist %v)", ccep != nil),
			logfields.CESName, cesName.string(),
			logfields.CEPName, cepName.string())
		if ccep != nil {
			newCES.Endpoints = append(newCES.Endpoints, *ccep)
		}
	}

	// Call the client API, to Create CES
	if _, err = r.client.CiliumEndpointSlices().Create(
		r.context, newCES, meta_v1.CreateOptions{}); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.InfoContext(r.context,
			"Unable to create CiliumEndpointSlice in k8s-apiserver",
			logfields.CESName, newCES.Name,
			logfields.Error, err)
	}
	return
}

// Update an existing CES
func (r *reconciler) reconcileCESUpdate(cesName CESName, cesObj *cilium_v2a1.CiliumEndpointSlice) (err error) {
	r.logger.DebugContext(r.context, "Reconciling CES Update", logfields.CESName, cesName.string())
	updatedCES := cesObj.DeepCopy()
	cepInserted := 0
	cepRemoved := 0
	cepUpdated := 0

	// Names of all CEPs that should be in the CES
	cepsAssignedToCES := r.cesManager.getCEPinCES(cesName)
	// Final endpoints list. CES endpoints will be set to this list.
	updatedEndpoints := make([]cilium_v2a1.CoreCiliumEndpoint, 0, len(cepsAssignedToCES))
	cepNameToCEP := make(map[CEPName]*cilium_v2a1.CoreCiliumEndpoint)
	// Get the CEPs objects from the CEP Store and map the names to them
	for _, cepName := range cepsAssignedToCES {
		ccep := r.endpointGetter.getCoreEndpointFromStore(cepName)
		r.logger.DebugContext(r.context,
			fmt.Sprintf("Adding CEP to existing CES (exist %v)", ccep != nil),
			logfields.CESName, cesName.string(),
			logfields.CEPName, cepName.string())
		if ccep != nil {
			updatedEndpoints = append(updatedEndpoints, *ccep)
			cepNameToCEP[cepName] = ccep
		}
		cepInserted = cepInserted + 1
	}
	// Grab metrics about number of inserted, updated and deleted CEPs and
	// determine whether CES needs to be updated at all.
	for _, ep := range updatedCES.Endpoints {
		epName := GetCEPNameFromCCEP(&ep, updatedCES.Namespace)
		if r.cesManager.isCEPinCES(epName, cesName) {
			cepInserted = cepInserted - 1
			if !ep.DeepEqual(cepNameToCEP[epName]) {
				cepUpdated = cepUpdated + 1
			}
		} else {
			cepRemoved = cepRemoved + 1
		}
	}
	updatedCES.Endpoints = updatedEndpoints
	r.logger.DebugContext(r.context,
		fmt.Sprintf("Inserted %d endpoints, updated %d endpoints, removed %d endpoints",
			cepInserted,
			cepUpdated,
			cepRemoved),
		logfields.CESName, cesName.string(),
	)

	cesEqual := cepInserted == 0 && cepUpdated == 0 && cepRemoved == 0
	ns := r.cesManager.getCESNamespace(cesName)
	if updatedCES.Namespace != ns {
		updatedCES.Namespace = ns
		cesEqual = false
	}

	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPInsert).Observe(float64(cepInserted + cepUpdated))
	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPRemove).Observe(float64(cepRemoved))

	if !cesEqual {
		r.logger.DebugContext(r.context, "CES changed, updating", logfields.CESName, cesName.string())
		// Call the client API, to Create CESs
		if _, err = r.client.CiliumEndpointSlices().Update(
			r.context, updatedCES, meta_v1.UpdateOptions{}); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.InfoContext(r.context,
				"Unable to update CiliumEndpointSlice in k8s-apiserver",
				logfields.CESName, updatedCES.Name,
				logfields.Error, err)
		}
	} else {
		r.logger.DebugContext(r.context, "CES up to date, skipping update", logfields.CESName, cesName.string())
	}
	return
}

// Delete the CES.
func (r *reconciler) reconcileCESDelete(ces *cilium_v2a1.CiliumEndpointSlice) (err error) {
	r.logger.DebugContext(r.context, "Reconciling CES Delete", logfields.CESName, ces.Name)
	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPRemove).Observe(float64(len(ces.Endpoints)))
	if err = r.client.CiliumEndpointSlices().Delete(
		r.context, ces.Name, meta_v1.DeleteOptions{}); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.InfoContext(r.context,
			"Unable to delete CiliumEndpointSlice in k8s-apiserver",
			logfields.CESName, ces.Name,
			logfields.Error, err)
		return
	}
	return
}

func (r *defaultReconciler) getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint {
	cepObj, exists, err := r.cepStore.GetByKey(cepName.key())
	if err == nil && exists {
		return k8s.ConvertCEPToCoreCEP(cepObj)
	}
	r.logger.DebugContext(r.context,
		fmt.Sprintf("Couldn't get CEP from Store (err=%v, exists=%v)", err, exists),
		logfields.CEPName, cepName.string(),
	)
	return nil
}

func (r *slimReconciler) getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint {
	podObj, exists, err := r.podStore.GetByKey(cepName.key())
	if err == nil && exists {
		return r.convertPodToCoreCEP(podObj)
	}
	r.logger.DebugContext(r.context,
		"Couldn't get Pod from Store",
		logfields.Error, err,
		logfields.Exists, exists,
		logfields.CEPName, cepName.string(),
	)
	return nil
}

// Converts a Pod to a CoreCiliumEndpoint object. Returns nil if no CID has been assigned
// to the pod.
// While getting the CoreCEP fields, we typically get the most up-to-date information
// from the pod object being reconciled.
// However, in the case of the CID, we used the
// cached selectedID from the local cescache, in order to reduce churn when duplicate
// CIDs exist for the same set of labels.
func (r *slimReconciler) convertPodToCoreCEP(pod *slim_corev1.Pod) *cilium_v2a1.CoreCiliumEndpoint {
	identityId, err := r.getPodIdentityIDFromCache(pod)
	if err != nil {
		r.logger.DebugContext(r.context, "Could not get pod identity ID",
			logfields.K8sPodName, pod.GetName(),
			logfields.K8sNamespace, pod.Namespace,
			logfields.Error, err,
		)
		return nil
	}

	networking, err := GetPodEndpointNetworking(pod)
	if err != nil {
		r.logger.DebugContext(r.context, "Could not get pod's endpoint networking",
			logfields.K8sPodName, pod.GetName(),
			logfields.K8sNamespace, pod.Namespace,
			logfields.Error, err,
		)
		return nil
	}

	encryptionKey, err := r.getEndpointEncryptionKey(pod)
	if err != nil {
		r.logger.DebugContext(r.context, "Could not get pod's endpoint encryption key",
			logfields.K8sPodName, pod.GetName(),
			logfields.K8sNamespace, pod.Namespace,
			logfields.Error, err,
		)
		return nil
	}

	namedPorts := r.getNamedPorts(pod)

	return &cilium_v2a1.CoreCiliumEndpoint{
		Name:       pod.GetName(),
		IdentityID: identityId,
		Networking: networking,
		Encryption: cilium_v2.EncryptionSpec{
			Key: encryptionKey,
		},
		NamedPorts:     namedPorts,
		ServiceAccount: pod.Spec.ServiceAccountName,
	}
}

// Get the identity ID for a given pod, from the local cescache.
func (r *slimReconciler) getPodIdentityIDFromCache(pod *slim_corev1.Pod) (int64, error) {
	cid, exists := r.manager.getCIDForCEP(GetCEPNameFromPod(pod))
	if !exists {
		return 0, fmt.Errorf("pod %s/%s has no known identity", pod.Namespace, pod.Name)
	}
	identityId, err := strconv.ParseInt(string(cid), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse CID %s name for pod %s/%s: %w", cid, pod.Namespace, pod.Name, err)
	}
	return identityId, nil
}

// Constructs an EndpointNetworking object for a given pod.
func GetPodEndpointNetworking(pod *slim_corev1.Pod) (*cilium_v2.EndpointNetworking, error) {
	addressPair := &cilium_v2.AddressPair{}

	if len(pod.Status.PodIPs) == 0 {
		return nil, fmt.Errorf("no IPs allocated to pod yet: %s", pod.GetName())
	}

	for _, podIP := range pod.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err != nil {
			return nil, err
		}

		if ip.Is4() {
			addressPair.IPV4 = ip.String()
		} else if ip.Is6() {
			addressPair.IPV6 = ip.String()
		}
	}

	if pod.GetHostIP() == "" {
		return nil, fmt.Errorf("no hostIP for pod yet: %s", pod.GetName())
	}

	networking := &cilium_v2.EndpointNetworking{
		Addressing: cilium_v2.AddressPairList{
			addressPair,
		},
		NodeIP: pod.GetHostIP(),
	}
	return networking, nil
}

func (r *slimReconciler) getEndpointEncryptionKey(pod *slim_corev1.Pod) (int, error) {
	if pod.Spec.NodeName == "" {
		return 0, fmt.Errorf("pod %s/%s is not yet scheduled to a node", pod.Namespace, pod.Name)
	}
	key, found := r.manager.getEndpointEncryptionKey(NodeName(pod.Spec.NodeName))
	if !found {
		return 0, fmt.Errorf("no encryption key found in cache for node %s", pod.Spec.NodeName)
	}
	return int(key), nil
}

func (r *reconciler) getNamedPorts(pod *slim_corev1.Pod) models.NamedPorts {
	namedPorts := make(models.NamedPorts, 0)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == "" {
				continue
			}

			proto, err := getProtocolString(port.Protocol)
			if err != nil {
				continue
			}

			p := &models.Port{
				Name:     port.Name,
				Protocol: proto,
				Port:     uint16(port.ContainerPort),
			}
			namedPorts = append(namedPorts, p)
		}
	}
	return namedPorts
}

// Convert a slim_corev1.Protocol to models.PortProtocol format.
func getProtocolString(p slim_corev1.Protocol) (string, error) {
	switch p {
	case slim_corev1.ProtocolTCP:
		return models.PortProtocolTCP, nil
	case slim_corev1.ProtocolUDP:
		return models.PortProtocolUDP, nil
	case slim_corev1.ProtocolSCTP:
		return models.PortProtocolSCTP, nil
	default:
		return "", fmt.Errorf("unknown protocol: %s", p)
	}
}

func (r *slimReconciler) getNodeNameForPod(pod *slim_corev1.Pod) (string, error) {
	if pod.Spec.NodeName == "" {
		return "", fmt.Errorf("pod has empty node name")
	}
	return pod.Spec.NodeName, nil
}

func getPodCIDKey(pod *slim_corev1.Pod, logger *slog.Logger, nsStore resource.Store[*slim_corev1.Namespace]) (*key.GlobalIdentity, error) {
	k8sLabels, err := ciliumidentity.GetRelevantLabelsForPod(logger, pod, nsStore)
	if err != nil {
		return nil, fmt.Errorf("failed to get relevant labels for pod: %w", err)
	}
	cidKey := key.GetCIDKeyFromLabels(k8sLabels, labels.LabelSourceK8s)
	return cidKey, nil
}
