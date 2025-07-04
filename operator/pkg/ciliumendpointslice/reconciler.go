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

	"github.com/spf13/cast"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	op_k8s "github.com/cilium/cilium/operator/k8s"
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
	"github.com/cilium/cilium/pkg/option"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// reconciler is used to sync the current (i.e. desired) state of the CESs in datastore into current state CESs in the k8s-apiserver.
// The source of truth is in local datastore.
type reconciler struct {
	logger          *slog.Logger
	client          clientset.CiliumV2alpha1Interface
	context         context.Context
	cesManager      *cesManager
	podStore        resource.Store[*slim_corev1.Pod]
	cesStore        resource.Store[*cilium_v2a1.CiliumEndpointSlice]
	ciliumNodeStore resource.Store[*cilium_v2.CiliumNode]
	namespaceStore  resource.Store[*slim_corev1.Namespace]
	cidStore        resource.Store[*cilium_v2.CiliumIdentity]
	metrics         *Metrics
}

// newReconciler creates and initializes a new reconciler.
func newReconciler(
	ctx context.Context,
	client clientset.CiliumV2alpha1Interface,
	cesMgr *cesManager,
	logger *slog.Logger,
	pods resource.Resource[*slim_corev1.Pod],
	ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
	ciliumNode resource.Resource[*cilium_v2.CiliumNode],
	namespace resource.Resource[*slim_corev1.Namespace],
	ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity],
	metrics *Metrics,
) *reconciler {
	podStore, _ := pods.Store(ctx)
	cesStore, _ := ciliumEndpointSlice.Store(ctx)
	ciliumNodeStore, _ := ciliumNode.Store(ctx)
	nsStore, _ := namespace.Store(ctx)
	cidStore, _ := ciliumIdentity.Store(ctx)
	return &reconciler{
		context:         ctx,
		logger:          logger,
		client:          client,
		cesManager:      cesMgr,
		podStore:        podStore,
		cesStore:        cesStore,
		ciliumNodeStore: ciliumNodeStore,
		cidStore:        cidStore,
		namespaceStore:  nsStore,
		metrics:         metrics,
	}
}

func (r *reconciler) reconcileCES(cesName CESName) (err error) {
	r.logger.Debug("Reconciling CES", logfields.CESName, cesName.string())
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
	r.logger.Debug("Reconciling CES Create", logfields.CESName, cesName.string())
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
		r.logger.Debug("Reconciling CES Create for CEP",
			logfields.CESName, cesName.string(),
			logfields.CEPName, cepName.string(),
		)
		ccep := r.getCoreEndpointFromStore(cepName)
		r.logger.Debug(fmt.Sprintf("Adding CEP to new CES (exist %v)", ccep != nil),
			logfields.CESName, cesName.string(),
			logfields.CEPName, cepName.string())
		if ccep != nil {
			newCES.Endpoints = append(newCES.Endpoints, *ccep)
		}
	}

	// Call the client API, to Create CES
	if _, err = r.client.CiliumEndpointSlices().Create(
		r.context, newCES, meta_v1.CreateOptions{}); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Info("Unable to create CiliumEndpointSlice in k8s-apiserver",
			logfields.CESName, newCES.Name,
			logfields.Error, err)
	}
	return
}

// Update an existing CES
func (r *reconciler) reconcileCESUpdate(cesName CESName, cesObj *cilium_v2a1.CiliumEndpointSlice) (err error) {
	r.logger.Debug("Reconciling CES Update", logfields.CESName, cesName.string())
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
		r.logger.Debug("Reconciling CES Update for CEP",
			logfields.CESName, cesName.string(),
			logfields.CEPName, cepName.string(),
		)
		ccep := r.getCoreEndpointFromStore(cepName)
		r.logger.Debug(fmt.Sprintf("Adding CEP to existing CES (exist %v)", ccep != nil),
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
	r.logger.Debug(fmt.Sprintf("Inserted %d endpoints, updated %d endpoints, removed %d endpoints", cepInserted,
		cepUpdated, cepRemoved),
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
		r.logger.Debug("CES changed, updating", logfields.CESName, cesName.string())
		// Call the client API, to Create CESs
		if _, err = r.client.CiliumEndpointSlices().Update(
			r.context, updatedCES, meta_v1.UpdateOptions{}); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Info("Unable to update CiliumEndpointSlice in k8s-apiserver",
				logfields.CESName, updatedCES.Name,
				logfields.Error, err)
		}
	} else {
		r.logger.Debug("CES up to date, skipping update", logfields.CESName, cesName.string())
	}
	return
}

// Delete the CES.
func (r *reconciler) reconcileCESDelete(ces *cilium_v2a1.CiliumEndpointSlice) (err error) {
	r.logger.Debug("Reconciling CES Delete", logfields.CESName, ces.Name)
	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPRemove).Observe(float64(len(ces.Endpoints)))
	if err = r.client.CiliumEndpointSlices().Delete(
		r.context, ces.Name, meta_v1.DeleteOptions{}); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Info("Unable to delete CiliumEndpointSlice in k8s-apiserver",
			logfields.CESName, ces.Name,
			logfields.Error, err)
		return
	}
	return
}

func (r *reconciler) getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint {
	r.logger.Debug("Getting CoreCiliumEndpoint from store",
		logfields.CEPName, cepName.string(),
	)
	podObj, exists, err := r.podStore.GetByKey(cepName.key())
	if err == nil && exists {
		return r.convertPodToCoreCEP(podObj)
	}
	r.logger.Debug(fmt.Sprintf("Couldn't get Pod from Store (err=%v, exists=%v)",
		err, exists),
		logfields.CEPName, cepName.string(),
	)
	return nil
}

// Converts a Pod to a CoreCiliumEndpoint object. Returns nil if no CID has been assigned
// to the pod.
// While getting the CoreCEP fields, we typically get the most up-to-date information
// from the pod object being reconciled. However, in the case of the CID, we used the
// cached selectedID from the local cescache, in order to reduce churn when duplicate
// CIDs exist for the same set of labels.
func (r *reconciler) convertPodToCoreCEP(pod *slim_corev1.Pod) *cilium_v2a1.CoreCiliumEndpoint {
	scopedLog := r.logger.With(
		logfields.K8sPodName, pod.GetName(),
		logfields.K8sNamespace, pod.Namespace,
	)

	scopedLog.Debug("Converting Pod to CoreCiliumEndpoint")
	identityId, err := r.getPodIdentityIDFromCache(pod)
	if err != nil {
		scopedLog.Info("Could not get pod identity ID",
			logfields.Error, err,
		)
		return nil
	}
	scopedLog.Debug("Found pod identity ID",
		logfields.Identity, identityId,
	)

	networking, err := GetPodEndpointNetworking(pod)
	if err != nil {
		scopedLog.Info("Could not get pod's endpoint networking",
			logfields.Error, err,
		)
		return nil
	}

	encryptionKey, err := r.getEndpointEncryptionKey(pod)
	if err != nil {
		scopedLog.Info("Could not get pod's endpoint encryption key",
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
		NamedPorts: namedPorts,
	}
}

// Get the identity ID for a given pod.
func (r *reconciler) getPodIdentityIDFromCache(pod *slim_corev1.Pod) (int64, error) {
	cid, exists := r.cesManager.getCIDForCEP(GetCEPNameFromPod(pod))
	if !exists {
		return 0, fmt.Errorf("pod %s/%s has no known identity", pod.Namespace, pod.Name)
	}
	identityId, err := strconv.ParseInt(cid.string(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse CID name: %w", err)
	}
	r.logger.Debug("Found pod identity ID",
		logfields.K8sPodName, pod.GetName(),
		logfields.K8sNamespace, pod.Namespace,
		logfields.Identity, identityId,
	)
	return identityId, nil
}

func (r *reconciler) getPodIdentity(cidKey *key.GlobalIdentity) (*cilium_v2.CiliumIdentity, error) {
	// k8sLabels, err := ciliumidentity.GetRelevantLabelsForPod(r.logger, pod, r.namespaceStore)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get relevant labels for pod: %w", err)
	// }
	// cidKey := key.GetCIDKeyFromLabels(k8sLabels, labels.LabelSourceK8s)
	storeCIDs, err := r.cidStore.ByIndex(k8s.ByKeyIndex, cidKey.GetKey())
	if err != nil {
		return nil, fmt.Errorf("failed to get CID from store: %w", err)
	}
	if len(storeCIDs) == 0 {
		return nil, fmt.Errorf("CID store is empty")
	}
	return storeCIDs[0], nil
}

func (r *reconciler) getPodCIDKey(pod *slim_corev1.Pod) (*key.GlobalIdentity, error) {
	k8sLabels, err := ciliumidentity.GetRelevantLabelsForPod(r.logger, pod, r.namespaceStore)
	if err != nil {
		return nil, fmt.Errorf("failed to get relevant labels for pod: %w", err)
	}
	cidKey := key.GetCIDKeyFromLabels(k8sLabels, labels.LabelSourceK8s)
	return cidKey, nil
}

func (r *reconciler) getEndpointEncryptionKey(pod *slim_corev1.Pod) (int, error) {
	switch {
	case option.Config.EnableWireguard:
		return cast.ToInt(wgtypes.StaticEncryptKey), nil
	case option.Config.EnableIPSec:
		ciliumNode, err := r.ciliumNodeStore.ByIndex(op_k8s.CiliumNodeIPIndex, pod.GetHostIP())
		if err != nil || ciliumNode == nil || len(ciliumNode) == 0 {
			return 0, fmt.Errorf("failed to get CiliumNode from store: %w", err)
		}
		return ciliumNode[0].Spec.Encryption.Key, nil
	default:
		return 0, nil
	}
}

func (r *reconciler) getNodeNameForPod(pod *slim_corev1.Pod) (string, error) {
	if pod.Spec.NodeName == "" {
		return "", fmt.Errorf("pod has empty node name")
	}
	return pod.Spec.NodeName, nil
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
