// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"strconv"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

type EndpointAPIManager interface {
	CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (*endpoint.Endpoint, int, error)
	DeleteEndpoint(id string) (int, error)
	DeleteEndpointByContainerID(containerID string) (nErrors int, err error)
	EndpointUpdate(id string, cfg *models.EndpointConfigurationSpec) error
	ModifyEndpointIdentityLabelsFromAPI(id string, add, del labels.Labels) (int, error)
}

type endpointAPIManager struct {
	logger *slog.Logger

	endpointManager   endpointmanager.EndpointManager
	endpointCreator   endpointcreator.EndpointCreator
	endpointCreations EndpointCreationManager
	endpointMetadata  endpointmetadata.EndpointMetadataFetcher

	bandwidthManager datapath.BandwidthManager
	clientset        k8sClient.Clientset
	cniConfigManager cni.CNIConfigManager
	ipam             *ipam.IPAM
}

var _ EndpointAPIManager = &endpointAPIManager{}

func invalidDataError(ep *endpoint.Endpoint, err error) (*endpoint.Endpoint, int, error) {
	ep.Logger(endpointAPIModuleID).Warn("Creation of endpoint failed due to invalid data", logfields.Error, err)
	if ep != nil {
		ep.SetState(endpoint.StateInvalid, "Invalid endpoint")
	}
	return nil, PutEndpointIDInvalidCode, err
}

func (m *endpointAPIManager) errorDuringCreation(ep *endpoint.Endpoint, err error) (*endpoint.Endpoint, int, error) {
	m.endpointManager.RemoveEndpoint(ep, endpoint.DeleteConfig{
		// The IP has been provided by the caller and must be released
		// by the caller
		NoIPRelease: true,
	})
	ep.Logger(endpointAPIModuleID).Warn("Creation of endpoint failed", logfields.Error, err)
	return nil, PutEndpointIDFailedCode, err
}

// createEndpoint attempts to create the endpoint corresponding to the change
// request that was specified.
func (m *endpointAPIManager) CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (*endpoint.Endpoint, int, error) {
	if option.Config.EnableEndpointRoutes {
		if epTemplate.DatapathConfiguration == nil {
			epTemplate.DatapathConfiguration = &models.EndpointDatapathConfiguration{}
		}

		// Indicate to insert a per endpoint route instead of routing
		// via cilium_host interface
		epTemplate.DatapathConfiguration.InstallEndpointRoute = true

		// EndpointRoutes mode enables two features:
		// - Install one route per endpoint into the route table
		// - Configure BPF programs at receive to the endpoint rather
		//   than implementing the receive policy at the transmit point
		//   for another device.
		// If an external agent configures the routing table, then we
		// don't need to configure routes for this endpoint. However,
		// we *do* need to configure the BPF programs at receive.
		if m.cniConfigManager.ExternalRoutingEnabled() {
			epTemplate.DatapathConfiguration.InstallEndpointRoute = false
		}

		// Since routing occurs via endpoint interface directly, BPF
		// program is needed on that device at egress as BPF program on
		// cilium_host interface is bypassed
		epTemplate.DatapathConfiguration.RequireEgressProg = true

		// Delegate routing to the Linux stack rather than tail-calling
		// between BPF programs.
		disabled := false
		epTemplate.DatapathConfiguration.RequireRouting = &disabled
	}

	m.logger.Info("Create endpoint request",
		logfields.EndpointAddressing, epTemplate.Addressing,
		logfields.ContainerID, epTemplate.ContainerID,
		logfields.ContainerInterface, epTemplate.ContainerInterfaceName,
		logfields.DatapathConfiguration, epTemplate.DatapathConfiguration,
		logfields.Interface, epTemplate.InterfaceName,
		logfields.K8sPodName, epTemplate.K8sNamespace+"/"+epTemplate.K8sPodName,
		logfields.K8sUID, epTemplate.K8sUID,
		logfields.Labels, epTemplate.Labels,
		logfields.EndpointSyncBuild, epTemplate.SyncBuildEndpoint,
	)

	// We don't need to create the endpoint with the labels. This might cause
	// the endpoint regeneration to not be triggered further down, with the
	// ep.UpdateLabels or the ep.RunMetadataResolver, because the regeneration
	// is only triggered in case the labels are changed, which they might not
	// change because NewEndpointFromChangeModel would contain the
	// epTemplate.Labels, the same labels we would be calling ep.UpdateLabels or
	// the ep.RunMetadataResolver.
	apiLabels := labels.NewLabelsFromModel(epTemplate.Labels)
	epTemplate.Labels = nil

	ep, err := m.endpointCreator.NewEndpointFromChangeModel(ctx, epTemplate)
	if err != nil {
		return invalidDataError(ep, fmt.Errorf("unable to parse endpoint parameters: %w", err))
	}

	oldEp := m.endpointManager.LookupCiliumID(ep.ID)
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint ID %d already exists", ep.ID))
	}

	oldEp = m.endpointManager.LookupCNIAttachmentID(ep.GetCNIAttachmentID())
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint for CNI attachment ID %s already exists", ep.GetCNIAttachmentID()))
	}

	var checkIDs []string

	if ep.IPv4.IsValid() {
		checkIDs = append(checkIDs, endpointid.NewID(endpointid.IPv4Prefix, ep.IPv4.String()))
	}

	if ep.IPv6.IsValid() {
		checkIDs = append(checkIDs, endpointid.NewID(endpointid.IPv6Prefix, ep.IPv6.String()))
	}

	for _, id := range checkIDs {
		oldEp, err := m.endpointManager.Lookup(id)
		if err != nil {
			return invalidDataError(ep, err)
		} else if oldEp != nil {
			return invalidDataError(ep, fmt.Errorf("IP %s is already in use", id))
		}
	}

	if err = endpoint.APICanModify(ep); err != nil {
		return invalidDataError(ep, err)
	}

	infoLabels := labels.NewLabelsFromModel([]string{})

	if len(apiLabels) > 0 {
		if lbls := apiLabels.FindReserved(); lbls != nil {
			return invalidDataError(ep, fmt.Errorf("not allowed to add reserved labels: %s", lbls))
		}

		apiLabels, _ = labelsfilter.Filter(apiLabels)
		if len(apiLabels) == 0 {
			return invalidDataError(ep, fmt.Errorf("no valid labels provided"))
		}
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	m.endpointCreations.NewCreateRequest(ep, cancel)
	defer m.endpointCreations.EndCreateRequest(ep)

	identityLbls := maps.Clone(apiLabels)

	if ep.K8sNamespaceAndPodNameIsSet() && m.clientset.IsEnabled() {
		pod, k8sMetadata, err := m.handleOutdatedPodInformer(ctx, ep)
		if errors.Is(err, endpointmetadata.ErrPodStoreOutdated) {
			m.logger.Warn("Timeout occurred waiting for Pod store, fetching latest Pod via the apiserver.",
				logfields.K8sPodName, ep.K8sNamespace+"/"+ep.K8sPodName,
				logfields.K8sUID, ep.K8sUID,
			)

			// Fetch the latest instance of the pod because
			// fetchK8sMetadataForEndpoint() returned a stale pod from the
			// store. If there's a mismatch in UIDs, this is an indication of a
			// StatefulSet workload that was restarted on the local node and we
			// must handle it as a special case. See GH-30409.
			if newPod, err2 := m.clientset.Slim().CoreV1().Pods(ep.K8sNamespace).Get(
				ctx, ep.K8sPodName, metav1.GetOptions{},
			); err2 != nil {
				ep.Logger("api").Warn(
					"Failed to fetch Kubernetes Pod during detection of an outdated Pod UID. Endpoint will be created with the 'init' identity. "+
						"The Endpoint will be updated with a real identity once the Kubernetes can be fetched.",
					logfields.Error, err2)
				err = errors.Join(err, err2)
			} else {
				pod = newPod
				// Clear the error so the code can proceed below, if the metadata
				// retrieval succeeds correctly.
				k8sMetadata, err = m.endpointMetadata.FetchK8sMetadataForEndpointFromPod(pod)
			}
		}

		if err != nil {
			ep.Logger("api").Warn("Unable to fetch kubernetes labels", logfields.Error, err)
		} else {
			ep.SetPod(pod)
			ep.SetK8sMetadata(k8sMetadata.ContainerPorts)
			identityLbls.MergeLabels(k8sMetadata.IdentityLabels)
			infoLabels.MergeLabels(k8sMetadata.InfoLabels)
			if _, ok := pod.Annotations[bandwidth.IngressBandwidth]; ok && !m.bandwidthManager.Enabled() {
				m.logger.Warn("Endpoint has bandwidth annotation, but BPF bandwidth manager is disabled. This annotation is ignored.",
					logfields.K8sPodName, epTemplate.K8sNamespace+"/"+epTemplate.K8sPodName,
					logfields.Annotation, bandwidth.IngressBandwidth,
					logfields.Annotations, pod.Annotations,
				)
			}
			if _, ok := pod.Annotations[bandwidth.EgressBandwidth]; ok && !m.bandwidthManager.Enabled() {
				m.logger.Warn("Endpoint has %s annotation, but BPF bandwidth manager is disabled. This annotation is ignored.",
					logfields.K8sPodName, epTemplate.K8sNamespace+"/"+epTemplate.K8sPodName,
					logfields.Annotation, bandwidth.EgressBandwidth,
					logfields.Annotations, pod.Annotations,
				)
			}
			if hwAddr, ok := pod.Annotations[annotation.PodAnnotationMAC]; !ep.GetDisableLegacyIdentifiers() && ok {
				mac, err := mac.ParseMAC(hwAddr)
				if err != nil {
					m.logger.Error("Unable to parse MAC address",
						logfields.Error, err,
						logfields.K8sPodName, epTemplate.K8sNamespace+"/"+epTemplate.K8sPodName,
					)
					return invalidDataError(ep, err)
				}
				ep.SetMac(mac)
			}

			if tid, ok := pod.Annotations[annotation.FIBTableID]; ok {
				if tidInt, err := strconv.ParseUint(tid, 10, 32); err == nil {
					ep.SetFibTableID(uint32(tidInt))
				} else {
					m.logger.Warn("Unable to parse fib-table-id annotation as uint32, pod will use default routing table.",
						logfields.K8sPodName, epTemplate.K8sPodName,
						logfields.Annotation, annotation.FIBTableID,
						logfields.Error, err,
					)
				}
			}
		}
	}

	// The following docs describe the cases where the init identity is used:
	// http://docs.cilium.io/en/latest/policy/lifecycle/#init-identity
	if len(identityLbls) == 0 {
		// If the endpoint has no labels, give the endpoint a special identity with
		// label reserved:init so we can generate a custom policy for it until we
		// get its actual identity.
		identityLbls = labels.Labels{
			labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
		}
	}

	// e.ID assigned here
	err = m.endpointManager.AddEndpoint(ep)
	if err != nil {
		return m.errorDuringCreation(ep, fmt.Errorf("unable to insert endpoint into manager: %w", err))
	}

	var regenTriggered bool
	if ep.K8sNamespaceAndPodNameIsSet() && m.clientset.IsEnabled() {
		// We need to refetch the pod labels again because we have just added
		// the endpoint into the endpoint manager. If we have received any pod
		// events, more specifically any events that modified the pod labels,
		// between the time the pod was created and the time it was added
		// into the endpoint manager, the pod event would not have been processed
		// since the pod event handler would not find the endpoint for that pod
		// in the endpoint manager. Thus, we will fetch the labels again
		// and update the endpoint with these labels.
		// Wait for the regeneration to be triggered before continuing.
		regenTriggered = ep.RunMetadataResolver(false, true, apiLabels, m.endpointMetadata.FetchK8sMetadataForEndpoint)
	} else {
		regenTriggered = ep.UpdateLabels(ctx, labels.LabelSourceAny, identityLbls, infoLabels, true)
	}

	select {
	case <-ctx.Done():
		return m.errorDuringCreation(ep, fmt.Errorf("request cancelled while resolving identity"))
	default:
	}

	if !regenTriggered {
		regenMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            "Initial build on endpoint creation",
			RegenerationLevel: regeneration.RegenerateWithDatapath,
		}
		build, err := ep.SetRegenerateStateIfAlive(regenMetadata)
		if err != nil {
			return m.errorDuringCreation(ep, err)
		}
		if build {
			ep.Regenerate(regenMetadata)
		}
	}

	if epTemplate.SyncBuildEndpoint {
		if err := ep.WaitForFirstRegeneration(ctx); err != nil {
			return m.errorDuringCreation(ep, err)
		}
	}

	// The endpoint has been successfully created, stop the expiration
	// timers of all attached IPs
	if addressing := epTemplate.Addressing; addressing != nil {
		if uuid := addressing.IPV4ExpirationUUID; uuid != "" {
			if ip := net.ParseIP(addressing.IPV4); ip != nil {
				pool := ipam.PoolOrDefault(addressing.IPV4PoolName)
				if err := m.ipam.StopExpirationTimer(ip, pool, uuid); err != nil {
					return m.errorDuringCreation(ep, err)
				}
			}
		}
		if uuid := addressing.IPV6ExpirationUUID; uuid != "" {
			if ip := net.ParseIP(addressing.IPV6); ip != nil {
				pool := ipam.PoolOrDefault(addressing.IPV6PoolName)
				if err := m.ipam.StopExpirationTimer(ip, pool, uuid); err != nil {
					return m.errorDuringCreation(ep, err)
				}
			}
		}
	}

	return ep, 0, nil
}

// handleOutdatedPodInformerRetryPeriod allows to configure the retry period for
// testing purposes.
var handleOutdatedPodInformerRetryPeriod = 100 * time.Millisecond

func (m *endpointAPIManager) handleOutdatedPodInformer(ctx context.Context, ep *endpoint.Endpoint) (pod *slim_corev1.Pod, k8sMetadata *endpoint.K8sMetadata, err error) {
	var once sync.Once

	// Average attempt is every 100ms.
	err = resiliency.Retry(ctx, handleOutdatedPodInformerRetryPeriod, 20, func(_ context.Context, _ int) (bool, error) {
		var err2 error
		pod, k8sMetadata, err2 = m.endpointMetadata.FetchK8sMetadataForEndpoint(ep.K8sNamespace, ep.K8sPodName, ep.K8sUID)
		if ep.K8sUID == "" {
			// If the CNI did not set the UID, then don't retry and just exit
			// out of the loop to proceed as normal.
			return true, err2
		}

		if errors.Is(err2, endpointmetadata.ErrPodStoreOutdated) {
			once.Do(func() {
				m.logger.Warn("Detected outdated Pod UID during Endpoint creation. Endpoint creation cannot proceed with an outdated Pod store. Attempting to fetch latest Pod.",
					logfields.K8sPodName, ep.K8sNamespace+"/"+ep.K8sPodName,
					logfields.K8sUID, ep.K8sUID,
				)
			})

			return false, nil
		}
		return true, err2
	})

	if wait.Interrupted(err) {
		return nil, nil, endpointmetadata.ErrPodStoreOutdated
	}

	return pod, k8sMetadata, err
}

func (m *endpointAPIManager) deleteEndpointRelease(ep *endpoint.Endpoint, noIPRelease bool) int {
	// Cancel any ongoing endpoint creation
	m.endpointCreations.CancelCreateRequest(ep)

	scopedLog := m.logger.With(logfields.EndpointID, ep.ID)
	// Set the endpoint into disconnecting state and remove
	// it from Cilium, releasing all resources associated with it such as its
	// visibility in the endpointmanager, its BPF programs and maps, (optional) IP,
	// L7 policy configuration, directories and controllers.
	//
	// Specific users such as the cilium-health EP may choose not to release the IP
	// when deleting the endpoint. Most users should pass true for releaseIP.
	errs := m.endpointManager.RemoveEndpoint(ep, endpoint.DeleteConfig{
		NoIPRelease: noIPRelease,
	})
	for _, err := range errs {
		scopedLog.Warn("Ignoring error while deleting endpoint", logfields.Error, err)
	}
	return len(errs)
}

func (m *endpointAPIManager) deleteEndpoint(ep *endpoint.Endpoint) int {
	// If the IP is managed by an external IPAM, it does not need to be released
	return m.deleteEndpointRelease(ep, ep.DatapathConfiguration.ExternalIpam)
}

func (m *endpointAPIManager) DeleteEndpoint(id string) (int, error) {
	if ep, err := m.endpointManager.Lookup(id); err != nil {
		return 0, api.Error(DeleteEndpointIDInvalidCode, err)
	} else if ep == nil {
		return 0, api.New(DeleteEndpointIDNotFoundCode, "endpoint not found")
	} else if err = endpoint.APICanModify(ep); err != nil {
		return 0, api.Error(DeleteEndpointIDInvalidCode, err)
	} else {
		msg := "Delete endpoint request"
		switch containerID := ep.GetShortContainerID(); containerID {
		case "":
			m.logger.Info(msg,
				logfields.IPv4, ep.GetIPv4Address(),
				logfields.IPv6, ep.GetIPv6Address(),
				logfields.EndpointID, ep.ID,
				logfields.K8sPodName, ep.GetK8sPodName(),
				logfields.K8sNamespace, ep.GetK8sNamespace(),
			)
		default:
			m.logger.Info(msg,
				logfields.ContainerID, containerID,
				logfields.EndpointID, ep.ID,
				logfields.K8sPodName, ep.GetK8sPodName(),
				logfields.K8sNamespace, ep.GetK8sNamespace(),
			)
		}
		return m.deleteEndpoint(ep), nil
	}
}

func (m *endpointAPIManager) DeleteEndpointByContainerID(containerID string) (nErrors int, err error) {
	if containerID == "" {
		return 0, api.New(DeleteEndpointInvalidCode, "invalid container id")
	}

	eps := m.endpointManager.GetEndpointsByContainerID(containerID)
	if len(eps) == 0 {
		return 0, api.New(DeleteEndpointNotFoundCode, "endpoints not found")
	}

	for _, ep := range eps {
		scopedLog := m.logger.With(
			logfields.ContainerID, containerID,
			logfields.EndpointID, ep.ID,
			logfields.K8sPodName, ep.GetK8sPodName(),
			logfields.K8sNamespace, ep.GetK8sNamespace(),
		)

		if err = endpoint.APICanModify(ep); err != nil {
			scopedLog.Warn("Skipped endpoint in batch delete request", logfields.Error, err)
			nErrors++
			continue
		}

		scopedLog.Info("Delete endpoint by containerID request")
		nErrors += m.deleteEndpoint(ep)
	}

	return nErrors, nil
}

// EndpointUpdate updates the options of the given endpoint and regenerates the endpoint
func (m *endpointAPIManager) EndpointUpdate(id string, cfg *models.EndpointConfigurationSpec) error {
	ep, err := m.endpointManager.Lookup(id)
	if err != nil {
		return api.Error(PatchEndpointIDInvalidCode, err)
	} else if ep == nil {
		return api.New(PatchEndpointIDConfigNotFoundCode, "endpoint %s not found", id)
	} else if err := ep.APICanModifyConfig(cfg.Options); err != nil {
		return api.Error(PatchEndpointIDInvalidCode, err)
	}

	if err := ep.Update(cfg); err != nil {
		var updateValidationError endpoint.UpdateValidationError
		if errors.As(err, &updateValidationError) {
			return api.Error(PatchEndpointIDConfigInvalidCode, err)
		}
		return api.Error(PatchEndpointIDConfigFailedCode, err)
	}
	if err := m.endpointManager.UpdateReferences(ep); err != nil {
		return api.Error(PatchEndpointIDNotFoundCode, err)
	}

	return nil
}

// modifyEndpointIdentityLabelsFromAPI adds and deletes the given labels on given endpoint ID.
// Performs checks for whether the endpoint may be modified by an API call.
// The received `add` and `del` labels will be filtered with the valid label prefixes.
// The `add` labels take precedence over `del` labels, this means if the same
// label is set on both `add` and `del`, that specific label will exist in the
// endpoint's labels.
// Returns an HTTP response code and an error msg (or nil on success).
func (m *endpointAPIManager) ModifyEndpointIdentityLabelsFromAPI(id string, add, del labels.Labels) (int, error) {
	addLabels, _ := labelsfilter.Filter(add)
	delLabels, _ := labelsfilter.Filter(del)
	if lbls := addLabels.FindReserved(); lbls != nil {
		return PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to add reserved labels: %s", lbls)
	} else if lbls := delLabels.FindReserved(); lbls != nil {
		return PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to delete reserved labels: %s", lbls)
	}

	ep, err := m.endpointManager.Lookup(id)
	if err != nil {
		return PatchEndpointIDInvalidCode, err
	}
	if ep == nil {
		return PatchEndpointIDLabelsNotFoundCode, fmt.Errorf("Endpoint ID %s not found", id)
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return PatchEndpointIDInvalidCode, err
	}

	if err := ep.ModifyIdentityLabels(labels.LabelSourceAny, addLabels, delLabels, 0); err != nil {
		return PatchEndpointIDLabelsNotFoundCode, err
	}

	return PatchEndpointIDLabelsOKCode, nil
}
