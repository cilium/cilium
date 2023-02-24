// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/bandwidth"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
)

var errEndpointNotFound = errors.New("endpoint not found")

// fetchK8sMetadataForEndpoint wraps the k8s package to fetch and provide
// endpoint metadata. It implements endpoint.MetadataResolverCB.
// The returned pod is deepcopied which means the its fields can be written
// into.
func (d *Daemon) fetchK8sMetadataForEndpoint(nsName, podName string) (*slim_corev1.Pod, []slim_corev1.ContainerPort, labels.Labels, labels.Labels, map[string]string, error) {
	ns, p, err := d.endpointMetadataFetcher.Fetch(nsName, podName)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	containerPorts, lbls, annotations, err := k8s.GetPodMetadata(ns, p)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	k8sLbls := labels.Map2Labels(lbls, labels.LabelSourceK8s)
	identityLabels, infoLabels := labelsfilter.Filter(k8sLbls)
	return p, containerPorts, identityLabels, infoLabels, annotations, nil
}

type cachedEndpointMetadataFetcher struct {
	k8sWatcher *watchers.K8sWatcher
}

func (cemf *cachedEndpointMetadataFetcher) Fetch(nsName, podName string) (*slim_corev1.Namespace, *slim_corev1.Pod, error) {
	p, err := cemf.k8sWatcher.GetCachedPod(nsName, podName)
	if err != nil {
		return nil, nil, err
	}
	ns, err := cemf.k8sWatcher.GetCachedNamespace(nsName)
	if err != nil {
		return nil, nil, err
	}
	return ns, p, err
}

type uncachedEndpointMetadataFetcher struct {
	slimcli slimclientset.Interface
}

func (uemf *uncachedEndpointMetadataFetcher) Fetch(nsName, podName string) (*slim_corev1.Namespace, *slim_corev1.Pod, error) {
	p, err := uemf.slimcli.CoreV1().Pods(nsName).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	ns, err := uemf.slimcli.CoreV1().Namespaces().Get(context.TODO(), nsName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	return ns, p, err
}

func invalidDataError(ep *endpoint.Endpoint, err error) (int, error) {
	ep.Logger(daemonSubsys).WithError(err).Warning("Creation of endpoint failed due to invalid data")
	if ep != nil {
		ep.SetState(endpoint.StateInvalid, "Invalid endpoint")
	}
	return PutEndpointIDInvalidCode, err
}

func (d *Daemon) errorDuringCreation(ep *endpoint.Endpoint, err error) (int, error) {
	d.endpointManager.RemoveEndpoint(ep,
		endpoint.DeleteConfig{
			// The IP has been provided by the caller and must be released
			// by the caller
			NoIPRelease: true,
		})
	ep.Logger(daemonSubsys).WithError(err).Warning("Creation of endpoint failed")
	return PutEndpointIDFailedCode, err
}

// CreateEndpoint attempts to create the endpoint corresponding to the change
// request that was specified.
func (d *Daemon) CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (int, error) {
	if option.Config.EnableEndpointRoutes {
		if epTemplate.DatapathConfiguration == nil {
			epTemplate.DatapathConfiguration = &models.EndpointDatapathConfiguration{}
		}

		// Indicate to insert a per endpoint route instead of routing
		// via cilium_host interface
		epTemplate.DatapathConfiguration.InstallEndpointRoute = true

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
		"addressing":            epTemplate.Addressing,
		logfields.ContainerID:   epTemplate.ContainerID,
		"datapathConfiguration": epTemplate.DatapathConfiguration,
		logfields.Interface:     epTemplate.InterfaceName,
		logfields.K8sPodName:    epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
		logfields.Labels:        epTemplate.Labels,
		"sync-build":            epTemplate.SyncBuildEndpoint,
	}).Info("Create endpoint request")

	ep, err := endpoint.NewEndpointFromChangeModel(d.ctx, d, d, d.ipcache, d.l7Proxy, d.identityAllocator, epTemplate)
	if err != nil {
		return invalidDataError(ep, fmt.Errorf("unable to parse endpoint parameters: %s", err))
	}

	oldEp := d.endpointManager.LookupCiliumID(ep.ID)
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint ID %d already exists", ep.ID))
	}

	oldEp = d.endpointManager.LookupContainerID(ep.GetContainerID())
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint for container %s already exists", ep.GetContainerID()))
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

	addLabels := labels.NewLabelsFromModel(epTemplate.Labels)
	infoLabels := labels.NewLabelsFromModel([]string{})

	if len(addLabels) > 0 {
		if lbls := addLabels.FindReserved(); lbls != nil {
			return invalidDataError(ep, fmt.Errorf("not allowed to add reserved labels: %s", lbls))
		}

		addLabels, _ = labelsfilter.Filter(addLabels)
		if len(addLabels) == 0 {
			return invalidDataError(ep, fmt.Errorf("no valid labels provided"))
		}
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	d.endpointCreations.NewCreateRequest(ep, cancel)
	defer d.endpointCreations.EndCreateRequest(ep)

	if ep.K8sNamespaceAndPodNameIsSet() && d.clientset.IsEnabled() {
		pod, cp, identityLabels, info, annotations, err := d.fetchK8sMetadataForEndpoint(ep.K8sNamespace, ep.K8sPodName)
		if err != nil {
			ep.Logger("api").WithError(err).Warning("Unable to fetch kubernetes labels")
		} else {
			ep.SetPod(pod)
			ep.SetK8sMetadata(cp)
			addLabels.MergeLabels(identityLabels)
			infoLabels.MergeLabels(info)
			if _, ok := annotations[bandwidth.IngressBandwidth]; ok {
				log.WithFields(logrus.Fields{
					logfields.K8sPodName:  epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
					logfields.Annotations: logfields.Repr(annotations),
				}).Warningf("Endpoint has %s annotation which is unsupported. This annotation is ignored.",
					bandwidth.IngressBandwidth)
			}
			if _, ok := annotations[bandwidth.EgressBandwidth]; ok && !option.Config.EnableBandwidthManager {
				log.WithFields(logrus.Fields{
					logfields.K8sPodName:  epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
					logfields.Annotations: logfields.Repr(annotations),
				}).Warningf("Endpoint has %s annotation, but BPF bandwidth manager is disabled. This annotation is ignored.",
					bandwidth.EgressBandwidth)
			}
		}
	}

	// The following docs describe the cases where the init identity is used:
	// http://docs.cilium.io/en/latest/policy/lifecycle/#init-identity
	if len(addLabels) == 0 {
		// If the endpoint has no labels, give the endpoint a special identity with
		// label reserved:init so we can generate a custom policy for it until we
		// get its actual identity.
		addLabels = labels.Labels{
			labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
		}
	}

	// Static pods (mirror pods) might be configured before the apiserver
	// is available or has received the notification that includes the
	// static pod's labels. In this case, start a controller to attempt to
	// resolve the labels.
	k8sLabelsConfigured := true
	if ep.K8sNamespaceAndPodNameIsSet() && d.clientset.IsEnabled() {
		// If there are labels, but no pod namespace, then it's
		// likely that there are no k8s labels at all. Resolve.
		if _, k8sLabelsConfigured = addLabels[k8sConst.PodNamespaceLabel]; !k8sLabelsConfigured {
			ep.RunMetadataResolver(d.fetchK8sMetadataForEndpoint)
		}
	}

	// e.ID assigned here
	err = d.endpointManager.AddEndpoint(d, ep, "Create endpoint from API PUT")
	if err != nil {
		return d.errorDuringCreation(ep, fmt.Errorf("unable to insert endpoint into manager: %s", err))
	}

	// We need to update the the visibility policy after adding the endpoint in
	// the endpoint manager because the endpoint manager create the endpoint
	// queue of the endpoint. If we execute this function before the endpoint
	// manager creates the endpoint queue the operation will fail.
	if ep.K8sNamespaceAndPodNameIsSet() && d.clientset.IsEnabled() && k8sLabelsConfigured {
		ep.UpdateVisibilityPolicy(func(ns, podName string) (proxyVisibility string, err error) {
			_, p, err := d.endpointMetadataFetcher.Fetch(ns, podName)
			if err != nil {
				return "", err
			}
			value, _ := annotation.Get(p, annotation.ProxyVisibility, annotation.ProxyVisibilityAlias)
			return value, nil
		})
		ep.UpdateBandwidthPolicy(func(ns, podName string) (bandwidthEgress string, err error) {
			_, p, err := d.endpointMetadataFetcher.Fetch(ns, podName)
			if err != nil {
				return "", err
			}
			return p.Annotations[bandwidth.EgressBandwidth], nil
		})
		ep.UpdateNoTrackRules(func(ns, podName string) (noTrackPort string, err error) {
			_, p, err := d.endpointMetadataFetcher.Fetch(ns, podName)
			if err != nil {
				return "", err
			}
			value, _ := annotation.Get(p, annotation.NoTrack, annotation.NoTrackAlias)
			return value, nil
		})
	}

	regenTriggered := ep.UpdateLabels(ctx, addLabels, infoLabels, true)

	select {
	case <-ctx.Done():
		return d.errorDuringCreation(ep, fmt.Errorf("request cancelled while resolving identity"))
	default:
	}

	if !regenTriggered {
		regenMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            "Initial build on endpoint creation",
			ParentContext:     ctx,
			RegenerationLevel: regeneration.RegenerateWithDatapathRewrite,
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

	ep.Logger(daemonSubsys).Info("Successful endpoint creation")
	return 0, nil
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

func (d *Daemon) PatchEndpoint(ctx context.Context, ID string, epTemplate *models.EndpointChangeRequest) (int, error) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.EndpointID:    epTemplate.ID,
		"addressing":            epTemplate.Addressing,
		logfields.ContainerID:   epTemplate.ContainerID,
		"datapathConfiguration": epTemplate.DatapathConfiguration,
		logfields.Interface:     epTemplate.InterfaceName,
		logfields.K8sPodName:    epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
		logfields.Labels:        epTemplate.Labels,
	})

	scopedLog.Info("Patch endpoint request")

	// Validate the template. Assignment afterwards is atomic.
	// Note: newEp's labels are ignored.
	newEp, err2 := endpoint.NewEndpointFromChangeModel(d.ctx, d, d, d.ipcache, d.l7Proxy, d.identityAllocator, epTemplate)
	if err2 != nil {
		return PatchEndpointIDInvalidCode, err2
	}

	var validStateTransition bool

	// Log invalid state transitions, but do not error out for backwards
	// compatibility.
	if !validPatchTransitionState(epTemplate.State) {
		scopedLog.Debugf("PATCH /endpoint/{id} to invalid state '%s'", *epTemplate.State)
	} else {
		validStateTransition = true
	}

	ep, err := d.endpointManager.Lookup(ID)
	if err != nil {
		return PatchEndpointIDInvalidCode, err
	}
	if ep == nil {
		return PatchEndpointIDNotFoundCode, errEndpointNotFound
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return PatchEndpointIDInvalidCode, err
	}

	// FIXME: Support changing these?
	//  - container ID
	//  - docker network id
	//  - docker endpoint id
	//
	//  Support arbitrary changes? Support only if unset?
	reason, err := ep.ProcessChangeRequest(newEp, validStateTransition)
	if err != nil {
		return PatchEndpointIDNotFoundCode, err
	}

	if reason != "" {
		regenMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            reason,
			RegenerationLevel: regeneration.RegenerateWithDatapathRewrite,
		}
		if !<-ep.Regenerate(regenMetadata) {
			err := api.Error(PatchEndpointIDFailedCode,
				fmt.Errorf("error while regenerating endpoint."+
					" For more info run: 'cilium endpoint get %d'", ep.ID))
			return PatchEndpointIDFailedCode, err
		}
		// FIXME: Special return code to indicate regeneration happened?
	}

	ep.Logger(daemonSubsys).Info("Successful endpoint patch")
	return PatchEndpointIDOKCode, nil
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

// EndpointDeleted is a callback to satisfy EndpointManager.Subscriber,
// which works around the difficulties in initializing various subsystems
// involved in managing endpoints, such as the EndpointManager, IPAM and
// the Monitor.
//
// It is called after Daemon calls into d.endpointManager.RemoveEndpoint().
func (d *Daemon) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	d.SendNotification(monitorAPI.EndpointDeleteMessage(ep))

	if !conf.NoIPRelease {
		if option.Config.EnableIPv4 {
			if err := d.ipam.ReleaseIP(ep.IPv4.AsSlice(), ipam.PoolOrDefault(ep.IPv4IPAMPool)); err != nil {
				scopedLog := ep.Logger(daemonSubsys).WithError(err)
				scopedLog.Warning("Unable to release IPv4 address during endpoint deletion")
			}
		}
		if option.Config.EnableIPv6 {
			if err := d.ipam.ReleaseIP(ep.IPv6.AsSlice(), ipam.PoolOrDefault(ep.IPv6IPAMPool)); err != nil {
				scopedLog := ep.Logger(daemonSubsys).WithError(err)
				scopedLog.Warning("Unable to release IPv6 address during endpoint deletion")
			}
		}
	}
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

func (d *Daemon) deleteEndpoint(ep *endpoint.Endpoint) int {
	// Cancel any ongoing endpoint creation
	d.endpointCreations.CancelCreateRequest(ep)

	scopedLog := log.WithField(logfields.EndpointID, ep.ID)
	errs := d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
		// If the IP is managed by an external IPAM, it does not need to be released
		NoIPRelease: ep.DatapathConfiguration.ExternalIpam,
	})
	for _, err := range errs {
		scopedLog.WithError(err).Warn("Ignoring error while deleting endpoint")
	}

	return len(errs)

}

// EndpointCreated is a callback to satisfy EndpointManager.Subscriber,
// allowing the EndpointManager to be the primary implementer of the core
// endpoint management functionality while deferring other responsibilities
// to the daemon.
//
// It is called after Daemon calls into d.endpointManager.AddEndpoint().
func (d *Daemon) EndpointCreated(ep *endpoint.Endpoint) {
	d.SendNotification(monitorAPI.EndpointCreateMessage(ep))
}

// QueueEndpointBuild waits for a "build permit" for the endpoint
// identified by 'epID'. This function blocks until the endpoint can
// start building.  The returned function must then be called to
// release the "build permit" when the most resource intensive parts
// of the build are done. The returned function is idempotent, so it
// may be called more than once. Returns a nil function if the caller should NOT
// start building the endpoint. This may happen due to a build being
// queued for the endpoint already, or due to the wait for the build
// permit being canceled. The latter case happens when the endpoint is
// being deleted. Returns an error if the build permit could not be acquired.
func (d *Daemon) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	// Acquire build permit. This may block.
	err := d.buildEndpointSem.Acquire(ctx, 1)

	if err != nil {
		return nil, err // Acquire failed
	}

	// Acquire succeeded, but the context was canceled after?
	if ctx.Err() != nil {
		d.buildEndpointSem.Release(1)
		return nil, ctx.Err()
	}

	// At this point the build permit has been acquired. It must
	// be released by the caller by calling the returned function
	// when the heavy lifting of the build is done.
	// Using sync.Once to make the returned function idempotent.
	var once sync.Once
	doneFunc := func() {
		once.Do(func() {
			d.buildEndpointSem.Release(1)
		})
	}
	return doneFunc, nil
}

func (d *Daemon) GetDNSRules(epID uint16) restore.DNSRules {
	if proxy.DefaultDNSProxy == nil {
		return nil
	}

	rules, err := proxy.DefaultDNSProxy.GetRules(epID)
	if err != nil {
		log.WithField(logfields.EndpointID, epID).WithError(err).Error("Could not get DNS rules")
		return nil
	}
	return rules
}

func (d *Daemon) RemoveRestoredDNSRules(epID uint16) {
	if proxy.DefaultDNSProxy == nil {
		return
	}

	proxy.DefaultDNSProxy.RemoveRestoredRules(epID)
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
	// The endpoint create logic already ensures that IPs and containerID
	// are unique and thus tracking is not required outside of the
	// Kubernetes context
	if !ep.K8sNamespaceAndPodNameIsSet() || !m.clientset.IsEnabled() {
		return
	}

	podName := ep.GetK8sNamespaceAndPodName()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if req, ok := m.requests[podName]; ok {
		ep.Logger("daemon").Warning("Cancelling obsolete endpoint creating due to new create for same pod")
		req.cancel()
	}

	ep.Logger("daemon").Debug("New create request")
	m.requests[podName] = &endpointCreationRequest{
		cancel:   cancel,
		endpoint: ep,
		started:  time.Now(),
	}
}

func (m *endpointCreationManager) EndCreateRequest(ep *endpoint.Endpoint) bool {
	if !ep.K8sNamespaceAndPodNameIsSet() || !m.clientset.IsEnabled() {
		return false
	}

	podName := ep.GetK8sNamespaceAndPodName()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if req, ok := m.requests[podName]; ok {
		if req.endpoint == ep {
			ep.Logger("daemon").Debug("End of create request")
			delete(m.requests, podName)
			return true
		}
	}

	return false
}

func (m *endpointCreationManager) CancelCreateRequest(ep *endpoint.Endpoint) {
	if m.EndCreateRequest(ep) {
		ep.Logger("daemon").Warning("Cancelled endpoint create request due to receiving endpoint delete request")
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
