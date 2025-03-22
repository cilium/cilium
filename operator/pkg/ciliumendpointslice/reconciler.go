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
	op_k8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/operator/pkg/ciliumidentity"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// reconciler is used to sync the current (i.e. desired) state of the CESs in datastore into current state CESs in the k8s-apiserver.
// The source of truth is in local datastore.
type reconciler struct {
	logger     *slog.Logger
	client     clientset.CiliumV2alpha1Interface
	context    context.Context
	cesManager operations
	//cepStore        resource.Store[*cilium_v2.CiliumEndpoint]
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
	cesMgr operations,
	logger *slog.Logger,
	//ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint],
	pods resource.Resource[*slim_corev1.Pod],
	ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
	ciliumNode resource.Resource[*cilium_v2.CiliumNode],
	namespace resource.Resource[*slim_corev1.Namespace],
	ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity],
	metrics *Metrics,
) *reconciler {
	//cepStore, _ := ciliumEndpoint.Store(ctx)
	podStore, _ := pods.Store(ctx)
	cesStore, _ := ciliumEndpointSlice.Store(ctx)
	ciliumNodeStore, _ := ciliumNode.Store(ctx)
	nsStore, _ := namespace.Store(ctx)
	cidStore, _ := ciliumIdentity.Store(ctx)
	return &reconciler{
		context:    ctx,
		logger:     logger,
		client:     client,
		cesManager: cesMgr,
		//cepStore:        cepStore,
		podStore:        podStore,
		cesStore:        cesStore,
		ciliumNodeStore: ciliumNodeStore,
		cidStore:        cidStore,
		namespaceStore:  nsStore,
		metrics:         metrics,
	}
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

	cesData := r.cesManager.getCESData(cesName)
	newCES.Namespace = cesData.ns

	for _, cepName := range ceps {
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
	data := r.cesManager.getCESData(cesName)
	if updatedCES.Namespace != data.ns {
		updatedCES.Namespace = data.ns
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

// TODO
// func (r *reconciler) getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint {
// 	// TODO: Fix this, temporarily just printing POD to Core CEP for testing.
// 	podObj, exists, err := r.podStore.GetByKey(cepName.key())
// 	if err == nil && exists {
// 		_ = r.podToCoreCEP(podObj)
// 	}

// 	cepObj, exists, err := r.cepStore.GetByKey(cepName.key())
// 	if err == nil && exists {
// 		return k8s.ConvertCEPToCoreCEP(cepObj)
// 	}
// 	r.logger.Debug(fmt.Sprintf("Couldn't get CEP from Store (err=%v, exists=%v)",
// 		err, exists),
// 		logfields.CEPName, cepName.string(),
// 	)
// 	return nil
// }

func (r *reconciler) getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint {
	// TODO: Fix this, temporarily just printing POD to Core CEP for testing.
	podObj, exists, err := r.podStore.GetByKey(cepName.key())
	if err == nil && exists {
		return r.podToCoreCEP(podObj)
	}
	r.logger.Debug(fmt.Sprintf("Couldn't get POD from Store (err=%v, exists=%v)",
		err, exists),
		logfields.CEPName, cepName.string(),
	)
	return nil

	// if err == nil && exists {
	// 	_ = r.podToCoreCEP(podObj)
	// }

	// cepObj, exists, err := r.cepStore.GetByKey(cepName.key())
	// if err == nil && exists {
	// 	return k8s.ConvertCEPToCoreCEP(cepObj)
	// }
	// r.logger.Debug(fmt.Sprintf("Couldn't get CEP from Store (err=%v, exists=%v)",
	// 	err, exists),
	// 	logfields.CEPName, cepName.string(),
	// )
	// return nil
}

// TODO
// Return CoreCEP or (CoreCEP, bool)?
func (r *reconciler) podToCoreCEP(pod *slim_corev1.Pod) *capi_v2a1.CoreCiliumEndpoint {
	// 1. Name string
	r.logger.Debug("coreCEP.Name", logfields.K8sPodName, pod.GetName())

	// 2. IdentityID int64
	k8sLabels, err := ciliumidentity.GetRelevantLabelsForPod(pod, r.namespaceStore)
	if err != nil {
		r.logger.Debug("failed to get relevant labels for pod", logfields.K8sPodName, pod.GetName(), logfields.Error, err)
		return nil
		//return fmt.Errorf("failed to get relevant labels for pod: %w", err)
	}

	cidKey := key.GetCIDKeyFromLabels(k8sLabels, labels.LabelSourceK8s)
	storeCIDs, err := r.cidStore.ByIndex(k8s.ByKeyIndex, cidKey.GetKey())
	if err != nil || storeCIDs == nil || len(storeCIDs) == 0 {
		r.logger.Debug("failed to get CID from store", logfields.K8sPodName, pod.GetName(), logfields.Error, err)
		return nil
	}
	identityId, err := strconv.ParseInt(storeCIDs[0].Name, 10, 64)
	if err != nil {
		r.logger.Debug("failed to parse CID name", logfields.K8sPodName, pod.GetName(), logfields.Error, err)
	}
	r.logger.Debug("coreCEP.IdentityID", logfields.K8sPodName, pod.GetName(), logfields.Identity, identityId)

	// 3. Networking *cilium_v2.EndpointNetworking
	addressPair := &cilium_api_v2.AddressPair{}
	for _, podIP := range pod.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err != nil {
			// TODO
			r.logger.Debug("podIP error", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace, logfields.IPAddr, podIP.IP, logfields.Error, err)
			return nil
		}
		if ip.Is4() {
			addressPair.IPV4 = ip.String()
			r.logger.Debug("podIP4", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace, logfields.IPAddr, podIP.IP)
		} else if ip.Is6() {
			addressPair.IPV6 = ip.String()
			r.logger.Debug("podIP6", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace, logfields.IPAddr, podIP.IP)
		} else {
			// TODO
			r.logger.Debug("podIP error", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace, logfields.IPAddr, podIP.IP, logfields.Error, err)
			return nil
		}
	}
	networking := &cilium_api_v2.EndpointNetworking{
		Addressing: cilium_api_v2.AddressPairList{
			addressPair,
		},
	}

	// 4. Encryption cilium_v2.EncryptionSpec
	if pod.GetHostIP() == "" {
		// TODO
		r.logger.Debug("no hostIP", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace)
		return nil
	}
	ciliumNode, err := r.ciliumNodeStore.ByIndex(op_k8s.CiliumNodeIPIndex, pod.GetHostIP())
	if err != nil || ciliumNode == nil || len(ciliumNode) == 0 {
		// TODO
		r.logger.Debug("no ciliumNode", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace, logfields.HostIP, pod.GetHostIP())
		return nil
	}
	r.logger.Debug("cilium node encryption key is ", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace, logfields.HostIP, pod.GetHostIP(), logfields.Key, ciliumNode[0].Spec.Encryption.Key)

	// 5. NamedPorts models.NamedPorts
	namedPorts := make(models.NamedPorts, 0)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == "" {
				continue
			}

			proto := getProtocolString(port.Protocol)
			if proto == "" {
				r.logger.Debug("unknown protocol", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace, logfields.PortName, port.Name, logfields.Protocol, port.Protocol)
				continue
			}

			p := &models.Port{
				Name:     port.Name,
				Protocol: proto,
				Port:     uint16(port.ContainerPort),
			}
			r.logger.Debug("named port", logfields.K8sPodName, pod.GetName(), logfields.K8sNamespace, pod.Namespace, logfields.PortName, port.Name, logfields.Protocol, port.Protocol, logfields.Port, port.ContainerPort)
			namedPorts = append(namedPorts, p)
		}
	}

	return &capi_v2a1.CoreCiliumEndpoint{
		Name:       pod.GetName(),
		IdentityID: identityId,
		Networking: networking,
		Encryption: ciliumNode[0].Spec.Encryption,
		NamedPorts: namedPorts,
	}
}

func getProtocolString(p slim_corev1.Protocol) string {
	switch p {
	case slim_corev1.ProtocolTCP:
		return models.PortProtocolTCP
	case slim_corev1.ProtocolUDP:
		return models.PortProtocolUDP
	case slim_corev1.ProtocolSCTP:
		return models.PortProtocolSCTP
	default:
		return ""
	}
}

// func validatePodHasIdentity(pod *slim_corev1.Pod, namespaceStore resource.Store[*slim_corev1.Namespace], cidStore resource.Store[*cilium_v2.CiliumIdentity], logger *slog.Logger) {
// 	k8sLabels, err := ciliumidentity.GetRelevantLabelsForPod(pod, namespaceStore)
// 	if err != nil {
// 		logger.Debug("failed to get relevant labels for pod", logfields.K8sPodName, pod.GetName(), logfields.Error, err)
// 		return nil
// 		//return fmt.Errorf("failed to get relevant labels for pod: %w", err)
// 	}

// 	cidKey := key.GetCIDKeyFromLabels(k8sLabels, labels.LabelSourceK8s)
// 	storeCIDs, err := r.cidStore.ByIndex(k8s.ByKeyIndex, cidKey.GetKey())
// 	if err != nil || storeCIDs == nil || len(storeCIDs) == 0 {
// 		r.logger.Debug("failed to get CID from store", logfields.K8sPodName, pod.GetName(), logfields.Error, err)
// 		return nil
// 	}
// 	identityId, err := strconv.ParseInt(storeCIDs[0].Name, 10, 64)
// 	if err != nil {
// 		r.logger.Debug("failed to parse CID name", logfields.K8sPodName, pod.GetName(), logfields.Error, err)
// 	}
// 	r.logger.Debug("coreCEP.IdentityID", logfields.K8sPodName, pod.GetName(), logfields.Identity, identityId)
// }
