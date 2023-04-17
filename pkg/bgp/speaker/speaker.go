// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package speaker abstracts the BGP speaker controller from MetalLB. This
// package provides BGP announcements based on K8s object event handling.
package speaker

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/bgp/fence"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discover_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discover_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	ErrShutDown = errors.New("cannot enqueue event, speaker is shutdown")
)

// compile time check, Speaker must be a subscriber.Node
var _ subscriber.Node = (*MetalLBSpeaker)(nil)

// New creates a new MetalLB BGP speaker controller. Options are provided to
// specify what the Speaker should announce via BGP.
func New(ctx context.Context, clientset client.Clientset, opts Opts) (*MetalLBSpeaker, error) {
	ctrl, err := newMetalLBSpeaker(ctx, clientset)
	if err != nil {
		return nil, err
	}
	spkr := &MetalLBSpeaker{
		Fencer:  fence.Fencer{},
		speaker: ctrl,

		announceLBIP:    opts.LoadBalancerIP,
		announcePodCIDR: opts.PodCIDR,

		queue: workqueue.New(),

		services: make(map[k8s.ServiceID]*slim_corev1.Service),
	}

	go spkr.run(ctx)

	log.Info("Started BGP speaker")

	return spkr, nil
}

// Opts represents what the Speaker can announce.
type Opts struct {
	LoadBalancerIP bool
	PodCIDR        bool
}

// MetalLBSpeaker represents the BGP speaker. It integrates Cilium's K8s events with
// MetalLB's logic for making BGP announcements. It is responsible for
// announcing BGP messages containing a loadbalancer IP address to peers.
type MetalLBSpeaker struct {
	// Our speaker requeues our own event structures on failure.
	// Use a fence to avoid replaying stale events.
	fence.Fencer
	// queue holds all the events to process for the Speaker.
	queue workqueue.Interface

	// a BGP speaker implementation
	speaker Speaker

	announceLBIP, announcePodCIDR bool

	endpointsGetter endpointsGetter

	lock.Mutex
	services map[k8s.ServiceID]*slim_corev1.Service

	// atomic boolean which is flipped when
	// speaker sees a NodeDelete events.
	//
	// Speaker will shut itself down when this is 1,
	// ensuring no other events are processed after the
	// final withdraw of routes.
	shutdown int32
}

func (s *MetalLBSpeaker) shutDown() bool {
	return atomic.LoadInt32(&s.shutdown) > 0
}

// OnUpdateService notifies the Speaker of an update to a service.
func (s *MetalLBSpeaker) OnUpdateService(svc *slim_corev1.Service) error {
	if s.shutDown() {
		return ErrShutDown
	}
	var (
		svcID = k8s.ParseServiceID(svc)
		l     = log.WithFields(logrus.Fields{
			"component":  "MetalLBSpeaker.OnUpdateService",
			"service-id": svcID,
		})
		meta = fence.Meta{}
	)

	eps := new(metallbspr.Endpoints)
	epsFromSvc := s.endpointsGetter.GetEndpointsOfService(svcID)
	if epsFromSvc != nil {
		eps = convertInternalEndpoints(epsFromSvc)
	}

	s.Lock()
	s.services[svcID] = svc
	s.Unlock()

	if err := meta.FromObjectMeta(&svc.ObjectMeta); err != nil {
		l.WithError(err).Error("failed to parse event metadata")
	}

	l.Debug("adding event to queue")
	s.queue.Add(svcEvent{
		Meta: meta,
		op:   Update,
		id:   svcID,
		svc:  convertService(svc),
		eps:  eps,
	})
	return nil
}

// OnDeleteService notifies the Speaker of a delete of a service.
func (s *MetalLBSpeaker) OnDeleteService(svc *slim_corev1.Service) error {
	if s.shutDown() {
		return ErrShutDown
	}
	var (
		svcID = k8s.ParseServiceID(svc)
		l     = log.WithFields(logrus.Fields{
			"component":  "MetalLBSpeaker.OnDeleteService",
			"service-id": svcID,
		})
		meta = fence.Meta{}
	)

	s.Lock()
	delete(s.services, svcID)
	s.Unlock()

	if err := meta.FromObjectMeta(&svc.ObjectMeta); err != nil {
		l.WithError(err).Error("failed to parse event metadata")
	}

	l.Debug("adding event to queue")
	// Passing nil as the service will force the MetalLB speaker to withdraw
	// the BGP announcement.
	s.queue.Add(svcEvent{
		Meta: meta,
		op:   Delete,
		id:   svcID,
		svc:  nil,
		eps:  nil,
	})
	return nil
}

// OnUpdateEndpoints notifies the Speaker of an update to the backends of a
// service.
func (s *MetalLBSpeaker) OnUpdateEndpoints(eps *slim_corev1.Endpoints) error {
	if s.shutDown() {
		return ErrShutDown
	}
	var (
		svcID = k8s.ParseEndpointsID(eps)
		l     = log.WithFields(logrus.Fields{
			"component":  "MetalLBSpeaker.OnUpdateEndpoints",
			"service-id": svcID,
		})
		meta = fence.Meta{}
	)

	s.Lock()
	defer s.Unlock()

	if err := meta.FromObjectMeta(&eps.ObjectMeta); err != nil {
		l.WithError(err).Error("failed to parse event metadata")
	}

	if svc, ok := s.services[svcID]; ok {
		l.Debug("adding event to queue")
		s.queue.Add(epEvent{
			Meta: meta,
			op:   Update,
			id:   svcID,
			svc:  convertService(svc),
			eps:  convertEndpoints(eps),
		})
	}
	return nil
}

// OnUpdateEndpointSliceV1 notifies the Speaker of an update to the backends of
// a service as endpoint slices.
func (s *MetalLBSpeaker) OnUpdateEndpointSliceV1(eps *slim_discover_v1.EndpointSlice) error {
	if s.shutDown() {
		return ErrShutDown
	}
	var (
		sliceID, _ = k8s.ParseEndpointSliceV1(eps)
		l          = log.WithFields(logrus.Fields{
			"component": "MetalLBSpeaker.OnUpdateEndpointSliceV1",
			"slice-id":  sliceID,
		})
		meta = fence.Meta{}
	)

	s.Lock()
	defer s.Unlock()

	if err := meta.FromObjectMeta(&eps.ObjectMeta); err != nil {
		l.WithError(err).Error("failed to parse event metadata")
	}

	if svc, ok := s.services[sliceID.ServiceID]; ok {
		l.Debug("adding event to queue")
		s.queue.Add(epEvent{
			Meta: meta,
			op:   Update,
			id:   sliceID.ServiceID,
			svc:  convertService(svc),
			eps:  convertEndpointSliceV1(eps),
		})
	}
	return nil
}

// OnUpdateEndpointSliceV1Beta1 is the same as OnUpdateEndpointSliceV1() but for
// the v1beta1 variant.
func (s *MetalLBSpeaker) OnUpdateEndpointSliceV1Beta1(eps *slim_discover_v1beta1.EndpointSlice) error {
	if s.shutDown() {
		return ErrShutDown
	}
	var (
		sliceID, _ = k8s.ParseEndpointSliceV1Beta1(eps)
		l          = log.WithFields(logrus.Fields{
			"component": "MetalLBSpeaker.OnUpdateEndpointSliceV1Beta",
			"slice-id":  sliceID,
		})
		meta = fence.Meta{}
	)

	s.Lock()
	defer s.Unlock()

	if err := meta.FromObjectMeta(&eps.ObjectMeta); err != nil {
		l.WithError(err).Error("failed to parse event metadata")
		return err
	}

	if svc, ok := s.services[sliceID.ServiceID]; ok {
		l.Debug("adding event to queue")
		s.queue.Add(epEvent{
			Meta: meta,
			op:   Update,
			id:   sliceID.ServiceID,
			svc:  convertService(svc),
			eps:  convertEndpointSliceV1Beta1(eps),
		})
	}
	return nil
}

type metaGetter interface {
	GetName() string
	GetResourceVersion() string
	GetUID() types.UID
	GetLabels() map[string]string
}

// notifyNodeEvent notifies the speaker of a node (K8s Node or CiliumNode) event
func (s *MetalLBSpeaker) notifyNodeEvent(op Op, nodeMeta metaGetter, podCIDRs *[]string, withDraw bool) error {
	if s.shutDown() {
		return ErrShutDown
	}
	if nodeMeta == nil || nodeMeta.GetName() != nodetypes.GetName() {
		return nil // We don't care for other nodes.
	}
	var (
		l = log.WithFields(logrus.Fields{
			"component": "MetalLBSpeaker.notifyNodeEvent",
			"op":        op.String(),
			"node":      nodeMeta.GetName(),
		})
		meta = fence.Meta{}
	)
	if err := meta.FromObjectMeta(nodeMeta); err != nil {
		l.WithError(err).Error("failed to parse event metadata")
		return err
	}

	l.Debug("adding event to queue")
	s.queue.Add(nodeEvent{
		Meta:     meta,
		op:       op,
		labels:   nodeLabels(nodeMeta.GetLabels()),
		podCIDRs: podCIDRs,
		withDraw: withDraw,
	})
	return nil
}

// OnAddNode notifies the Speaker of a new node.
func (s *MetalLBSpeaker) OnAddNode(node *slim_corev1.Node, swg *lock.StoppableWaitGroup) error {
	return s.notifyNodeEvent(Add, node, nodePodCIDRs(node), false)
}

func (s *MetalLBSpeaker) OnUpdateNode(oldNode, newNode *slim_corev1.Node, swg *lock.StoppableWaitGroup) error {
	return s.notifyNodeEvent(Update, newNode, nodePodCIDRs(newNode), false)
}

// OnDeleteNode notifies the Speaker of a node deletion.
//
// When the speaker discovers the node that it is running on
// is shuttig down it will send a BGP message to its peer
// instructing it to withdrawal all previously advertised
// routes.
func (s *MetalLBSpeaker) OnDeleteNode(node *slim_corev1.Node, swg *lock.StoppableWaitGroup) error {
	return s.notifyNodeEvent(Delete, node, nodePodCIDRs(node), true)
}

// OnAddCiliumNode notifies the Speaker of a new CiliumNode.
func (s *MetalLBSpeaker) OnAddCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	return s.notifyNodeEvent(Add, node, ciliumNodePodCIDRs(node), false)
}

// OnUpdateCiliumNode notifies the Speaker of an update to a CiliumNode.
func (s *MetalLBSpeaker) OnUpdateCiliumNode(oldNode, newNode *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	return s.notifyNodeEvent(Update, newNode, ciliumNodePodCIDRs(newNode), false)
}

// OnDeleteCiliumNode notifies the Speaker of a CiliumNode deletion.
//
// When the speaker discovers the node that it is running on
// is shuttig down it will send a BGP message to its peer
// instructing it to withdrawal all previously advertised
// routes.
func (s *MetalLBSpeaker) OnDeleteCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	return s.notifyNodeEvent(Delete, node, ciliumNodePodCIDRs(node), true)
}

// RegisterSvcCache registers the K8s watcher cache with this Speaker.
func (s *MetalLBSpeaker) RegisterSvcCache(cache endpointsGetter) {
	s.endpointsGetter = cache
}

// endpointsGetter abstracts the github.com/cilium/cilium/pkg/k8s.ServiceCache
// object. The cache holds all services and endpoints (backends) from the K8s
// watchers.
type endpointsGetter interface {
	GetEndpointsOfService(svcID k8s.ServiceID) *k8s.Endpoints
}

func convertService(in *slim_corev1.Service) *metallbspr.Service {
	if in == nil {
		return nil
	}
	ing := make([]v1.LoadBalancerIngress, len(in.Status.LoadBalancer.Ingress))
	for i := range in.Status.LoadBalancer.Ingress {
		ing[i].IP = in.Status.LoadBalancer.Ingress[i].IP
	}
	return &metallbspr.Service{
		Type:          string(in.Spec.Type),
		TrafficPolicy: string(in.Spec.ExternalTrafficPolicy),
		Ingress:       ing,
	}
}

func convertInternalEndpoints(in *k8s.Endpoints) *metallbspr.Endpoints {
	if in == nil {
		return nil
	}
	out := new(metallbspr.Endpoints)
	for addrCluster, be := range in.Backends {
		ep := metallbspr.Endpoint{
			IP:       addrCluster.Addr().String(),
			NodeName: &be.NodeName,
		}
		out.Ready = append(out.Ready, ep)
	}
	return out
}

func convertEndpoints(in *slim_corev1.Endpoints) *metallbspr.Endpoints {
	if in == nil {
		return nil
	}
	out := new(metallbspr.Endpoints)
	for _, sub := range in.Subsets {
		for _, ep := range sub.Addresses {
			out.Ready = append(out.Ready, metallbspr.Endpoint{
				IP:       ep.IP,
				NodeName: ep.NodeName,
			})
		}
		// MetalLB uses the NotReadyAddresses field to know which endpoints are
		// unhealthy in order to prevent BGP announcements until the endpoints
		// are ready. However, Cilium has no need for this field because
		// there's no need to also store unhealthy backends. The absence of
		// backends inside Addresses (healthy) is equivalent to the presence of
		// backends inside NotReadyAddresses. Therefore, Cilium chooses not to
		// include NotReadyAddresses inside its slim version of Endpoints. This
		// is still compatible with MetalLB because the information is
		// equivalent.
	}
	return out
}

func convertEndpointSliceV1(in *slim_discover_v1.EndpointSlice) *metallbspr.Endpoints {
	if in == nil {
		return nil
	}
	out := new(metallbspr.Endpoints)
	for _, ep := range in.Endpoints {
		if isConditionReadyForSliceV1(ep.Conditions) {
			for _, addr := range ep.Addresses {
				out.Ready = append(out.Ready, metallbspr.Endpoint{
					IP:       addr,
					NodeName: ep.NodeName,
				})
			}
		}
		// See above comment in convertEndpoints() for why we only append
		// "ready" endpoints.
	}
	return out
}

func isConditionReadyForSliceV1(conditions slim_discover_v1.EndpointConditions) bool {
	if conditions.Ready == nil {
		return true
	}
	return *conditions.Ready
}

func convertEndpointSliceV1Beta1(in *slim_discover_v1beta1.EndpointSlice) *metallbspr.Endpoints {
	if in == nil {
		return nil
	}
	out := new(metallbspr.Endpoints)
	for _, ep := range in.Endpoints {
		if isConditionReadyForSliceV1Beta1(ep.Conditions) {
			for _, addr := range ep.Addresses {
				out.Ready = append(out.Ready, metallbspr.Endpoint{
					IP:       addr,
					NodeName: ep.NodeName,
				})
			}
		}
		// See above comment in convertEndpoints() for why we only append
		// "ready" endpoints.
	}
	return out
}

func isConditionReadyForSliceV1Beta1(conditions slim_discover_v1beta1.EndpointConditions) bool {
	if conditions.Ready == nil {
		return true
	}
	return *conditions.Ready
}

// nodeLabels copies the provided labels and returns
// a pointer to the copy.
func nodeLabels(l map[string]string) *map[string]string {
	n := make(map[string]string)
	for k, v := range l {
		n[k] = v
	}
	return &n
}

func nodePodCIDRs(node *slim_corev1.Node) *[]string {
	if node == nil {
		return nil
	}
	podCIDRs := make([]string, 0, len(node.Spec.PodCIDRs))
	// this bit of code extracts the pod cidr block the node will
	// use per: https://github.com//cilium/cilium/blob/8cb6ca42179a0e325131a4c95b14291799d22e5c/vendor/k8s.io/api/core/v1/types.go#L4600
	// read the above comments to understand this access pattern.
	if pc := node.Spec.PodCIDR; pc != "" {
		if len(node.Spec.PodCIDRs) > 0 && pc != node.Spec.PodCIDRs[0] {
			podCIDRs = append(podCIDRs, pc)
		}
	}
	podCIDRs = append(podCIDRs, node.Spec.PodCIDRs...)
	return &podCIDRs
}

func ciliumNodePodCIDRs(node *ciliumv2.CiliumNode) *[]string {
	if node == nil {
		return nil
	}
	podCIDRs := make([]string, 0, len(node.Spec.IPAM.PodCIDRs))
	podCIDRs = append(podCIDRs, node.Spec.IPAM.PodCIDRs...)
	return &podCIDRs
}
