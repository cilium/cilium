// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/daemon/restapi"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

var errEndpointNotFound = errors.New("endpoint not found")

func getEndpointHandler(d *Daemon, params GetEndpointParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointList)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	resEPs := d.getEndpointList(params)

	if params.Labels != nil && len(resEPs) == 0 {
		r.Error(errEndpointNotFound, GetEndpointNotFoundCode)
		return NewGetEndpointNotFound()
	}

	return NewGetEndpointOK().WithPayload(resEPs)
}

func (d *Daemon) getEndpointList(params GetEndpointParams) []*models.Endpoint {
	maxGoroutines := runtime.NumCPU()
	var (
		epWorkersWg, epsAppendWg sync.WaitGroup
		convertedLabels          labels.Labels
		resEPs                   []*models.Endpoint
	)

	if params.Labels != nil {
		// Convert params.Labels to model that we can compare with the endpoint's labels.
		convertedLabels = labels.NewLabelsFromModel(params.Labels)
	}

	eps := d.endpointManager.GetEndpoints()
	if len(eps) < maxGoroutines {
		maxGoroutines = len(eps)
	}
	epsCh := make(chan *endpoint.Endpoint, maxGoroutines)
	epModelsCh := make(chan *models.Endpoint, maxGoroutines)

	epWorkersWg.Add(maxGoroutines)
	for i := 0; i < maxGoroutines; i++ {
		// Run goroutines to process each endpoint and the corresponding model.
		// The obtained endpoint model is sent to the endpoint models channel from
		// where it will be aggregated later.
		go func(wg *sync.WaitGroup, epModelsChan chan<- *models.Endpoint, epsChan <-chan *endpoint.Endpoint) {
			for ep := range epsChan {
				if ep.HasLabels(convertedLabels) {
					epModelsChan <- ep.GetModel()
				}
			}
			wg.Done()
		}(&epWorkersWg, epModelsCh, epsCh)
	}

	// Send the endpoints to be aggregated a models to the endpoint channel.
	go func(epsChan chan<- *endpoint.Endpoint, eps []*endpoint.Endpoint) {
		for _, ep := range eps {
			epsChan <- ep
		}
		close(epsChan)
	}(epsCh, eps)

	epsAppendWg.Add(1)
	// This needs to be done over channels since we might not receive all
	// the existing endpoints since not all endpoints contain the list of
	// labels that we will use to filter in `ep.HasLabels(convertedLabels)`
	go func(epsAppended *sync.WaitGroup) {
		for ep := range epModelsCh {
			resEPs = append(resEPs, ep)
		}
		epsAppended.Done()
	}(&epsAppendWg)

	epWorkersWg.Wait()
	close(epModelsCh)
	epsAppendWg.Wait()

	return resEPs
}

func deleteEndpointHandler(d *Daemon, params DeleteEndpointParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /endpoint/ request")

	if params.Endpoint.ContainerID == "" {
		return api.New(DeleteEndpointInvalidCode, "invalid container id")
	}

	// Bypass the rate limiter for endpoints that have already been deleted.
	// Kubelet will generate at minimum 2 delete requests for a Pod, so this
	// returns in earlier retruns for over half of all delete calls.
	if eps := d.endpointManager.GetEndpointsByContainerID(params.Endpoint.ContainerID); len(eps) == 0 {
		return api.New(DeleteEndpointNotFoundCode, "endpoints not found")
	}

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointDelete)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if nerr, err := d.deleteEndpointByContainerID(params.Endpoint.ContainerID); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, DeleteEndpointInvalidCode)
		return api.Error(DeleteEndpointInvalidCode, err)
	} else if nerr > 0 {
		return NewDeleteEndpointErrors().WithPayload(int64(nerr))
	}

	return NewDeleteEndpointOK()
}

func getEndpointIDHandler(d *Daemon, params GetEndpointIDParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id} request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDNotFoundCode)
		return NewGetEndpointIDNotFound()
	} else {
		return NewGetEndpointIDOK().WithPayload(ep.GetModel())
	}
}

// fetchK8sMetadataForEndpoint wraps the k8s package to fetch and provide
// endpoint metadata. It implements endpoint.MetadataResolverCB.
// The returned pod is deepcopied which means the its fields can be written
// into. Returns an error If a uid is given, and the uid of the retrieved
// pod does not match it.
func (d *Daemon) fetchK8sMetadataForEndpoint(nsName, podName, uid string) (*slim_corev1.Pod, *endpoint.K8sMetadata, error) {
	p, err := d.endpointMetadataFetcher.FetchPod(nsName, podName)
	if err != nil {
		return nil, nil, err
	}

	if uid != "" && uid != string(p.GetUID()) {
		return nil, nil, podStoreOutdatedErr
	}

	metadata, err := d.fetchK8sMetadataForEndpointFromPod(p)
	return p, metadata, err
}

func (d *Daemon) fetchK8sMetadataForEndpointFromPod(p *slim_corev1.Pod) (*endpoint.K8sMetadata, error) {
	ns, err := d.endpointMetadataFetcher.FetchNamespace(p.Namespace)
	if err != nil {
		return nil, err
	}

	containerPorts, lbls := k8s.GetPodMetadata(logging.DefaultSlogLogger, ns, p)
	k8sLbls := labels.Map2Labels(lbls, labels.LabelSourceK8s)
	identityLabels, infoLabels := labelsfilter.Filter(k8sLbls)
	return &endpoint.K8sMetadata{
		ContainerPorts: containerPorts,
		IdentityLabels: identityLabels,
		InfoLabels:     infoLabels,
	}, nil
}

type cachedEndpointMetadataFetcher struct {
	k8sWatcher *watchers.K8sWatcher
}

func (cemf *cachedEndpointMetadataFetcher) FetchNamespace(nsName string) (*slim_corev1.Namespace, error) {
	// If network policies are disabled, labels are not needed, the namespace
	// watcher is not running, and a namespace containing only the name is returned.
	if !option.NetworkPolicyEnabled(option.Config) {
		return &slim_corev1.Namespace{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: nsName,
			},
		}, nil
	}
	return cemf.k8sWatcher.GetCachedNamespace(nsName)
}

func (cemf *cachedEndpointMetadataFetcher) FetchPod(nsName, podName string) (*slim_corev1.Pod, error) {
	return cemf.k8sWatcher.GetCachedPod(nsName, podName)
}

func invalidDataError(ep *endpoint.Endpoint, err error) (*endpoint.Endpoint, int, error) {
	ep.Logger(daemonSubsys).WithError(err).Warning("Creation of endpoint failed due to invalid data")
	if ep != nil {
		ep.SetState(endpoint.StateInvalid, "Invalid endpoint")
	}
	return nil, PutEndpointIDInvalidCode, err
}

func (d *Daemon) errorDuringCreation(ep *endpoint.Endpoint, err error) (*endpoint.Endpoint, int, error) {
	d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
		// The IP has been provided by the caller and must be released
		// by the caller
		NoIPRelease: true,
	})
	ep.Logger(daemonSubsys).WithError(err).Warning("Creation of endpoint failed")
	return nil, PutEndpointIDFailedCode, err
}

type endpointCreationRequest struct {
	// cancel is the cancellation function that can be called to cancel
	// this endpoint create request
	cancel context.CancelFunc

	// endpoint is the endpoint being added in the request
	endpoint *endpoint.Endpoint

	// started is the timestamp on when the processing has started
	started time.Time
}

type endpointCreationManager struct {
	mutex     lock.Mutex
	clientset client.Clientset
	requests  map[string]*endpointCreationRequest
}

func newEndpointCreationManager(cs client.Clientset) *endpointCreationManager {
	return &endpointCreationManager{
		requests:  map[string]*endpointCreationRequest{},
		clientset: cs,
	}
}

func (m *endpointCreationManager) NewCreateRequest(ep *endpoint.Endpoint, cancel context.CancelFunc) {
	// Tracking is only performed if Kubernetes pod names are available.
	// The endpoint create logic already ensures that IPs and CNI attachment ID
	// are unique and thus tracking is not required outside of the
	// Kubernetes context
	if !ep.K8sNamespaceAndPodNameIsSet() || !m.clientset.IsEnabled() {
		return
	}

	cepName := ep.GetK8sNamespaceAndCEPName()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if req, ok := m.requests[cepName]; ok {
		ep.Logger(daemonSubsys).Warning("Cancelling obsolete endpoint creating due to new create for same cep name")
		req.cancel()
	}

	ep.Logger(daemonSubsys).Debug("New create request")
	m.requests[cepName] = &endpointCreationRequest{
		cancel:   cancel,
		endpoint: ep,
		started:  time.Now(),
	}
}

func (m *endpointCreationManager) EndCreateRequest(ep *endpoint.Endpoint) bool {
	if !ep.K8sNamespaceAndPodNameIsSet() || !m.clientset.IsEnabled() {
		return false
	}

	cepName := ep.GetK8sNamespaceAndCEPName()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if req, ok := m.requests[cepName]; ok {
		if req.endpoint == ep {
			ep.Logger(daemonSubsys).Debug("End of create request")
			delete(m.requests, cepName)
			return true
		}
	}

	return false
}

func (m *endpointCreationManager) CancelCreateRequest(ep *endpoint.Endpoint) {
	if m.EndCreateRequest(ep) {
		ep.Logger(daemonSubsys).Warning("Cancelled endpoint create request due to receiving endpoint delete request")
	}
}

func (m *endpointCreationManager) DebugStatus() (output string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, req := range m.requests {
		output += fmt.Sprintf("- %s: %s\n", req.started.String(), req.endpoint.String())
	}
	return
}

// createEndpoint attempts to create the endpoint corresponding to the change
// request that was specified.
func (d *Daemon) createEndpoint(ctx context.Context, dnsRulesApi endpoint.DNSRulesAPI, epTemplate *models.EndpointChangeRequest) (*endpoint.Endpoint, int, error) {
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
		if d.cniConfigManager.ExternalRoutingEnabled() {
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

	log.WithFields(logrus.Fields{
		"addressing":                 epTemplate.Addressing,
		logfields.ContainerID:        epTemplate.ContainerID,
		logfields.ContainerInterface: epTemplate.ContainerInterfaceName,
		"datapathConfiguration":      epTemplate.DatapathConfiguration,
		logfields.Interface:          epTemplate.InterfaceName,
		logfields.K8sPodName:         epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
		logfields.K8sUID:             epTemplate.K8sUID,
		logfields.Labels:             epTemplate.Labels,
		"sync-build":                 epTemplate.SyncBuildEndpoint,
	}).Info("Create endpoint request")

	// We don't need to create the endpoint with the labels. This might cause
	// the endpoint regeneration to not be triggered further down, with the
	// ep.UpdateLabels or the ep.RunMetadataResolver, because the regeneration
	// is only triggered in case the labels are changed, which they might not
	// change because NewEndpointFromChangeModel would contain the
	// epTemplate.Labels, the same labels we would be calling ep.UpdateLabels or
	// the ep.RunMetadataResolver.
	apiLabels := labels.NewLabelsFromModel(epTemplate.Labels)
	epTemplate.Labels = nil

	ep, err := endpoint.NewEndpointFromChangeModel(d.ctx, dnsRulesApi, d.epBuildQueue, d.loader, d.orchestrator, d.compilationLock, d.bwManager, d.iptablesManager, d.idmgr, d.monitorAgent, d.policyMapFactory, d.policy, d.ipcache, d.l7Proxy, d.identityAllocator, d.ctMapGC, epTemplate)
	if err != nil {
		return invalidDataError(ep, fmt.Errorf("unable to parse endpoint parameters: %w", err))
	}

	oldEp := d.endpointManager.LookupCiliumID(ep.ID)
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint ID %d already exists", ep.ID))
	}

	oldEp = d.endpointManager.LookupCNIAttachmentID(ep.GetCNIAttachmentID())
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
		oldEp, err := d.endpointManager.Lookup(id)
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

	if apiLabels.Len() > 0 {
		if lbls := apiLabels.FindReserved(); lbls.IsEmpty() {
			return invalidDataError(ep, fmt.Errorf("not allowed to add reserved labels: %s", lbls))
		}

		apiLabels, _ = labelsfilter.Filter(apiLabels)
		if apiLabels.Len() == 0 {
			return invalidDataError(ep, fmt.Errorf("no valid labels provided"))
		}
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	d.endpointCreations.NewCreateRequest(ep, cancel)
	defer d.endpointCreations.EndCreateRequest(ep)

	identityLbls := apiLabels

	if ep.K8sNamespaceAndPodNameIsSet() && d.clientset.IsEnabled() {
		pod, k8sMetadata, err := d.handleOutdatedPodInformer(ctx, ep)
		if errors.Is(err, podStoreOutdatedErr) {
			log.WithFields(logrus.Fields{
				logfields.K8sPodName: ep.K8sNamespace + "/" + ep.K8sPodName,
				logfields.K8sUID:     ep.K8sUID,
			}).Warn("Timeout occurred waiting for Pod store, fetching latest Pod via the apiserver.")

			// Fetch the latest instance of the pod because
			// fetchK8sMetadataForEndpoint() returned a stale pod from the
			// store. If there's a mismatch in UIDs, this is an indication of a
			// StatefulSet workload that was restarted on the local node and we
			// must handle it as a special case. See GH-30409.
			if newPod, err2 := d.clientset.Slim().CoreV1().Pods(ep.K8sNamespace).Get(
				ctx, ep.K8sPodName, metav1.GetOptions{},
			); err2 != nil {
				ep.Logger("api").WithError(err2).Warn(
					"Failed to fetch Kubernetes Pod during detection of an outdated Pod UID. Endpoint will be created with the 'init' identity. " +
						"The Endpoint will be updated with a real identity once the Kubernetes can be fetched.")
				err = errors.Join(err, err2)
			} else {
				pod = newPod
				// Clear the error so the code can proceed below, if the metadata
				// retrieval succeeds correctly.
				k8sMetadata, err = d.fetchK8sMetadataForEndpointFromPod(pod)
			}
		}

		if err != nil {
			ep.Logger("api").WithError(err).Warning("Unable to fetch kubernetes labels")
		} else {
			ep.SetPod(pod)
			ep.SetK8sMetadata(k8sMetadata.ContainerPorts)
			identityLbls = identityLbls.Merge(k8sMetadata.IdentityLabels)
			infoLabels = infoLabels.Merge(k8sMetadata.InfoLabels)
			if _, ok := pod.Annotations[bandwidth.IngressBandwidth]; ok && !d.bwManager.Enabled() {
				log.WithFields(logrus.Fields{
					logfields.K8sPodName:  epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
					logfields.Annotations: logfields.Repr(pod.Annotations),
				}).Warningf("Endpoint has %s annotation, but BPF bandwidth manager is disabled. This annotation is ignored.",
					bandwidth.IngressBandwidth)
			}
			if _, ok := pod.Annotations[bandwidth.EgressBandwidth]; ok && !d.bwManager.Enabled() {
				log.WithFields(logrus.Fields{
					logfields.K8sPodName:  epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
					logfields.Annotations: logfields.Repr(pod.Annotations),
				}).Warningf("Endpoint has %s annotation, but BPF bandwidth manager is disabled. This annotation is ignored.",
					bandwidth.EgressBandwidth)
			}
			if hwAddr, ok := pod.Annotations[annotation.PodAnnotationMAC]; !ep.GetDisableLegacyIdentifiers() && ok {
				m, err := mac.ParseMAC(hwAddr)
				if err != nil {
					log.WithField(logfields.K8sPodName, epTemplate.K8sNamespace+"/"+epTemplate.K8sPodName).
						WithError(err).Error("Unable to parse MAC address")
					return invalidDataError(ep, err)
				}
				ep.SetMac(m)
			}
		}
	}

	// The following docs describe the cases where the init identity is used:
	// http://docs.cilium.io/en/latest/policy/lifecycle/#init-identity
	if identityLbls.Len() == 0 {
		// If the endpoint has no labels, give the endpoint a special identity with
		// label reserved:init so we can generate a custom policy for it until we
		// get its actual identity.
		identityLbls = labels.NewLabels(labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved))

	}

	// e.ID assigned here
	err = d.endpointManager.AddEndpoint(ep)
	if err != nil {
		return d.errorDuringCreation(ep, fmt.Errorf("unable to insert endpoint into manager: %w", err))
	}

	var regenTriggered bool
	if ep.K8sNamespaceAndPodNameIsSet() && d.clientset.IsEnabled() {
		// We need to refetch the pod labels again because we have just added
		// the endpoint into the endpoint manager. If we have received any pod
		// events, more specifically any events that modified the pod labels,
		// between the time the pod was created and the time it was added
		// into the endpoint manager, the pod event would not have been processed
		// since the pod event handler would not find the endpoint for that pod
		// in the endpoint manager. Thus, we will fetch the labels again
		// and update the endpoint with these labels.
		// Wait for the regeneration to be triggered before continuing.
		regenTriggered = ep.RunMetadataResolver(false, true, apiLabels, d.bwManager, d.fetchK8sMetadataForEndpoint)
	} else {
		regenTriggered = ep.UpdateLabels(ctx, labels.LabelSourceAny, identityLbls, infoLabels, true)
	}

	select {
	case <-ctx.Done():
		return d.errorDuringCreation(ep, fmt.Errorf("request cancelled while resolving identity"))
	default:
	}

	if !regenTriggered {
		regenMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            "Initial build on endpoint creation",
			ParentContext:     ctx,
			RegenerationLevel: regeneration.RegenerateWithDatapath,
		}
		build, err := ep.SetRegenerateStateIfAlive(regenMetadata)
		if err != nil {
			return d.errorDuringCreation(ep, err)
		}
		if build {
			ep.Regenerate(regenMetadata)
		}
	}

	if epTemplate.SyncBuildEndpoint {
		if err := ep.WaitForFirstRegeneration(ctx); err != nil {
			return d.errorDuringCreation(ep, err)
		}
	}

	// The endpoint has been successfully created, stop the expiration
	// timers of all attached IPs
	if addressing := epTemplate.Addressing; addressing != nil {
		if uuid := addressing.IPV4ExpirationUUID; uuid != "" {
			if ip := net.ParseIP(addressing.IPV4); ip != nil {
				pool := ipam.PoolOrDefault(addressing.IPV4PoolName)
				if err := d.ipam.StopExpirationTimer(ip, pool, uuid); err != nil {
					return d.errorDuringCreation(ep, err)
				}
			}
		}
		if uuid := addressing.IPV6ExpirationUUID; uuid != "" {
			if ip := net.ParseIP(addressing.IPV6); ip != nil {
				pool := ipam.PoolOrDefault(addressing.IPV4PoolName)
				if err := d.ipam.StopExpirationTimer(ip, pool, uuid); err != nil {
					return d.errorDuringCreation(ep, err)
				}
			}
		}
	}

	return ep, 0, nil
}

// handleOutdatedPodInformerRetryPeriod allows to configure the retry period for
// testing purposes.
var handleOutdatedPodInformerRetryPeriod = 100 * time.Millisecond

func (d *Daemon) handleOutdatedPodInformer(
	ctx context.Context,
	ep *endpoint.Endpoint,
) (pod *slim_corev1.Pod, k8sMetadata *endpoint.K8sMetadata, err error) {
	var once sync.Once

	// Average attempt is every 100ms.
	err = resiliency.Retry(ctx, handleOutdatedPodInformerRetryPeriod, 20, func(_ context.Context, _ int) (bool, error) {
		var err2 error
		pod, k8sMetadata, err2 = d.fetchK8sMetadataForEndpoint(ep.K8sNamespace, ep.K8sPodName, ep.K8sUID)
		if ep.K8sUID == "" {
			// If the CNI did not set the UID, then don't retry and just exit
			// out of the loop to proceed as normal.
			return true, err2
		}

		if errors.Is(err2, podStoreOutdatedErr) {
			once.Do(func() {
				log.WithFields(logrus.Fields{
					logfields.K8sPodName: ep.K8sNamespace + "/" + ep.K8sPodName,
					logfields.K8sUID:     ep.K8sUID,
				}).Warn("Detected outdated Pod UID during Endpoint creation. Endpoint creation cannot proceed with an outdated Pod store. Attempting to fetch latest Pod.")
			})

			return false, nil
		}
		return true, err2
	})

	if wait.Interrupted(err) {
		return nil, nil, podStoreOutdatedErr
	}

	return pod, k8sMetadata, err
}

var podStoreOutdatedErr = errors.New("pod store outdated")

func putEndpointIDHandler(d *Daemon, params PutEndpointIDParams) (resp middleware.Responder) {
	if ep := params.Endpoint; ep != nil {
		log.WithField("endpoint", logfields.Repr(*ep)).Debug("PUT /endpoint/{id} request")
	} else {
		log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /endpoint/{id} request")
	}
	epTemplate := params.Endpoint

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointCreate)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, code, err := d.createEndpoint(params.HTTPRequest.Context(), d.dnsRulesAPI, epTemplate)
	if err != nil {
		r.Error(err, code)
		return api.Error(code, err)
	}

	ep.Logger(daemonSubsys).Info("Successful endpoint creation")

	return NewPutEndpointIDCreated().WithPayload(ep.GetModel())
}

// validPatchTransitionState checks whether the state to which the provided
// model specifies is one to which an Endpoint can transition as part of a
// call to PATCH on an Endpoint.
func validPatchTransitionState(state *models.EndpointState) bool {
	if state != nil {
		switch endpoint.State(*state) {
		case "", endpoint.StateWaitingForIdentity, endpoint.StateReady:
			return true
		}
	}
	return false
}

func patchEndpointIDHandler(d *Daemon, params PatchEndpointIDParams) middleware.Responder {
	scopedLog := log.WithField(logfields.Params, logfields.Repr(params))
	if ep := params.Endpoint; ep != nil {
		scopedLog = scopedLog.WithField("endpoint", logfields.Repr(*ep))
	}
	scopedLog.Debug("PATCH /endpoint/{id} request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	epTemplate := params.Endpoint

	log.WithFields(logrus.Fields{
		logfields.EndpointID:         params.ID,
		"addressing":                 epTemplate.Addressing,
		logfields.ContainerID:        epTemplate.ContainerID,
		logfields.ContainerInterface: epTemplate.ContainerInterfaceName,
		"datapathConfiguration":      epTemplate.DatapathConfiguration,
		logfields.Interface:          epTemplate.InterfaceName,
		logfields.K8sPodName:         epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
		logfields.Labels:             epTemplate.Labels,
	}).Info("Patch endpoint request")

	// Validate the template. Assignment afterwards is atomic.
	// Note: newEp's labels are ignored.
	newEp, err2 := endpoint.NewEndpointFromChangeModel(d.ctx, d.dnsRulesAPI, d.epBuildQueue, d.loader, d.orchestrator, d.compilationLock, d.bwManager, d.iptablesManager, d.idmgr, d.monitorAgent, d.policyMapFactory, d.policy, d.ipcache, d.l7Proxy, d.identityAllocator, d.ctMapGC, epTemplate)
	if err2 != nil {
		r.Error(err2, PutEndpointIDInvalidCode)
		return api.Error(PutEndpointIDInvalidCode, err2)
	}

	var validStateTransition bool

	// Log invalid state transitions, but do not error out for backwards
	// compatibility.
	if !validPatchTransitionState(epTemplate.State) {
		scopedLog.Debugf("PATCH /endpoint/{id} to invalid state '%s'", *epTemplate.State)
	} else {
		validStateTransition = true
	}

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		r.Error(errEndpointNotFound, PatchEndpointIDNotFoundCode)
		return NewPatchEndpointIDNotFound()
	}
	if err = endpoint.APICanModify(ep); err != nil {
		r.Error(err, PatchEndpointIDInvalidCode)
		return api.Error(PatchEndpointIDInvalidCode, err)
	}

	// FIXME: Support changing these?
	//  - container ID
	//  - docker network id
	//  - docker endpoint id
	//
	//  Support arbitrary changes? Support only if unset?
	reason, err := ep.ProcessChangeRequest(newEp, validStateTransition)
	if err != nil {
		r.Error(err, PatchEndpointIDNotFoundCode)
		return NewPatchEndpointIDNotFound()
	}

	if reason != "" {
		regenMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            reason,
			RegenerationLevel: regeneration.RegenerateWithDatapath,
		}
		if !<-ep.Regenerate(regenMetadata) {
			err := api.Error(PatchEndpointIDFailedCode,
				fmt.Errorf("error while regenerating endpoint."+
					" For more info run: 'cilium endpoint get %d'", ep.ID))
			r.Error(err, PatchEndpointIDFailedCode)
			return err
		}
		// FIXME: Special return code to indicate regeneration happened?
	}

	return NewPatchEndpointIDOK()
}

func (d *Daemon) deleteEndpointRelease(ep *endpoint.Endpoint, noIPRelease bool) int {
	// Cancel any ongoing endpoint creation
	d.endpointCreations.CancelCreateRequest(ep)

	scopedLog := log.WithField(logfields.EndpointID, ep.ID)
	errs := d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
		NoIPRelease: noIPRelease,
	})
	for _, err := range errs {
		scopedLog.WithError(err).Warn("Ignoring error while deleting endpoint")
	}
	return len(errs)
}

func (d *Daemon) deleteEndpoint(ep *endpoint.Endpoint) int {
	// If the IP is managed by an external IPAM, it does not need to be released
	return d.deleteEndpointRelease(ep, ep.DatapathConfiguration.ExternalIpam)
}

// deleteEndpointQuiet sets the endpoint into disconnecting state and removes
// it from Cilium, releasing all resources associated with it such as its
// visibility in the endpointmanager, its BPF programs and maps, (optional) IP,
// L7 policy configuration, directories and controllers.
//
// Specific users such as the cilium-health EP may choose not to release the IP
// when deleting the endpoint. Most users should pass true for releaseIP.
func (d *Daemon) deleteEndpointQuiet(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	return d.endpointManager.RemoveEndpoint(ep, conf)
}

func (d *Daemon) DeleteEndpoint(id string) (int, error) {
	if ep, err := d.endpointManager.Lookup(id); err != nil {
		return 0, api.Error(DeleteEndpointIDInvalidCode, err)
	} else if ep == nil {
		return 0, api.New(DeleteEndpointIDNotFoundCode, "endpoint not found")
	} else if err = endpoint.APICanModify(ep); err != nil {
		return 0, api.Error(DeleteEndpointIDInvalidCode, err)
	} else {
		msg := "Delete endpoint request"
		switch containerID := ep.GetShortContainerID(); containerID {
		case "":
			log.WithFields(logrus.Fields{
				logfields.IPv4:         ep.GetIPv4Address(),
				logfields.IPv6:         ep.GetIPv6Address(),
				logfields.EndpointID:   ep.ID,
				logfields.K8sPodName:   ep.GetK8sPodName(),
				logfields.K8sNamespace: ep.GetK8sNamespace(),
			}).Info(msg)
		default:
			log.WithFields(logrus.Fields{
				logfields.ContainerID:  containerID,
				logfields.EndpointID:   ep.ID,
				logfields.K8sPodName:   ep.GetK8sPodName(),
				logfields.K8sNamespace: ep.GetK8sNamespace(),
			}).Info(msg)
		}
		return d.deleteEndpoint(ep), nil
	}
}

func (d *Daemon) deleteEndpointByContainerID(containerID string) (nErrors int, err error) {
	if containerID == "" {
		return 0, api.New(DeleteEndpointInvalidCode, "invalid container id")
	}

	eps := d.endpointManager.GetEndpointsByContainerID(containerID)
	if len(eps) == 0 {
		return 0, api.New(DeleteEndpointNotFoundCode, "endpoints not found")
	}

	for _, ep := range eps {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.ContainerID:  containerID,
			logfields.EndpointID:   ep.ID,
			logfields.K8sPodName:   ep.GetK8sPodName(),
			logfields.K8sNamespace: ep.GetK8sNamespace(),
		})

		if err = endpoint.APICanModify(ep); err != nil {
			scopedLog.WithError(err).Warn("Skipped endpoint in batch delete request")
			nErrors++
			continue
		}

		scopedLog.Info("Delete endpoint by containerID request")
		nErrors += d.deleteEndpoint(ep)
	}

	return nErrors, nil
}

func deleteEndpointIDHandler(d *Daemon, params DeleteEndpointIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /endpoint/{id} request")

	// Bypass the rate limiter for endpoints that have already been deleted.
	// Kubelet will generate at minimum 2 delete requests for a Pod, so this
	// returns in earlier retruns for over half of all delete calls.
	if ep, err := d.endpointManager.Lookup(params.ID); err != nil {
		return api.Error(GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		return NewGetEndpointIDNotFound()
	}

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointDelete)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if nerr, err := d.DeleteEndpoint(params.ID); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, DeleteEndpointIDErrorsCode)
		return api.Error(DeleteEndpointIDErrorsCode, err)
	} else if nerr > 0 {
		return NewDeleteEndpointIDErrors().WithPayload(int64(nerr))
	}

	return NewDeleteEndpointIDOK()
}

// EndpointUpdate updates the options of the given endpoint and regenerates the endpoint
func (d *Daemon) EndpointUpdate(id string, cfg *models.EndpointConfigurationSpec) error {
	ep, err := d.endpointManager.Lookup(id)
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
	if err := d.endpointManager.UpdateReferences(ep); err != nil {
		return api.Error(PatchEndpointIDNotFoundCode, err)
	}

	return nil
}

func patchEndpointIDConfigHandler(d *Daemon, params PatchEndpointIDConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/config request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if err := d.EndpointUpdate(params.ID, params.EndpointConfiguration); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, PatchEndpointIDFailedCode)
		return api.Error(PatchEndpointIDFailedCode, err)
	}

	return NewPatchEndpointIDConfigOK()
}

func getEndpointIDConfigHandler(d *Daemon, params GetEndpointIDConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/config")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDConfigNotFoundCode)
		return NewGetEndpointIDConfigNotFound()
	} else {
		cfgStatus := ep.GetConfigurationStatus()

		return NewGetEndpointIDConfigOK().WithPayload(cfgStatus)
	}
}

func getEndpointIDLabelsHandler(d *Daemon, params GetEndpointIDLabelsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/labels")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDLabelsNotFoundCode)
		return NewGetEndpointIDLabelsNotFound()
	}

	cfg, err := ep.GetLabelsModel()
	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	}

	return NewGetEndpointIDLabelsOK().WithPayload(cfg)
}

func getEndpointIDLogHandler(d *Daemon, params GetEndpointIDLogParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, GetEndpointIDLogInvalidCode)
		return api.Error(GetEndpointIDLogInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDLogNotFoundCode)
		return NewGetEndpointIDLogNotFound()
	} else {
		return NewGetEndpointIDLogOK().WithPayload(ep.GetStatusModel())
	}
}

func getEndpointIDHealthzHandler(d *Daemon, params GetEndpointIDHealthzParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, GetEndpointIDHealthzInvalidCode)
		return api.Error(GetEndpointIDHealthzInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDHealthzNotFoundCode)
		return NewGetEndpointIDHealthzNotFound()
	} else {
		return NewGetEndpointIDHealthzOK().WithPayload(ep.GetHealthModel())
	}
}

// modifyEndpointIdentityLabelsFromAPI adds and deletes the given labels on given endpoint ID.
// Performs checks for whether the endpoint may be modified by an API call.
// The received `add` and `del` labels will be filtered with the valid label prefixes.
// The `add` labels take precedence over `del` labels, this means if the same
// label is set on both `add` and `del`, that specific label will exist in the
// endpoint's labels.
// Returns an HTTP response code and an error msg (or nil on success).
func (d *Daemon) modifyEndpointIdentityLabelsFromAPI(id string, add, del labels.Labels) (int, error) {
	addLabels, _ := labelsfilter.Filter(add)
	delLabels, _ := labelsfilter.Filter(del)
	if lbls := addLabels.FindReserved(); lbls.IsEmpty() {
		return PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to add reserved labels: %s", lbls)
	} else if lbls := delLabels.FindReserved(); lbls.IsEmpty() {
		return PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to delete reserved labels: %s", lbls)
	}

	ep, err := d.endpointManager.Lookup(id)
	if err != nil {
		return PatchEndpointIDInvalidCode, err
	}
	if ep == nil {
		return PatchEndpointIDLabelsNotFoundCode, fmt.Errorf("Endpoint ID %s not found", id)
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return PatchEndpointIDInvalidCode, err
	}

	if err := ep.ModifyIdentityLabels(labels.LabelSourceAny, addLabels, delLabels); err != nil {
		return PatchEndpointIDLabelsNotFoundCode, err
	}

	return PatchEndpointIDLabelsOKCode, nil
}

func putEndpointIDLabelsHandler(d *Daemon, params PatchEndpointIDLabelsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/labels request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	mod := params.Configuration
	lbls := labels.NewLabelsFromModel(mod.User)

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, PutEndpointIDInvalidCode)
		return api.Error(PutEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, PatchEndpointIDLabelsNotFoundCode)
		return NewPatchEndpointIDLabelsNotFound()
	}

	add, del, err := ep.ApplyUserLabelChanges(lbls)
	if err != nil {
		r.Error(err, PutEndpointIDInvalidCode)
		return api.Error(PutEndpointIDInvalidCode, err)
	}

	code, err := d.modifyEndpointIdentityLabelsFromAPI(params.ID, add, del)
	if err != nil {
		r.Error(err, code)
		return api.Error(code, err)
	}
	return NewPatchEndpointIDLabelsOK()
}
