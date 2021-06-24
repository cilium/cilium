// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package speaker abstracts the BGP speaker controller from MetalLB. This
// package provides BGP announcements based on K8s object event handling.
package speaker

import (
	"os"

	bgpconfig "github.com/cilium/cilium/pkg/bgp/config"
	bgpk8s "github.com/cilium/cilium/pkg/bgp/k8s"
	bgplog "github.com/cilium/cilium/pkg/bgp/log"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	metallbspr "go.universe.tf/metallb/pkg/speaker"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/workqueue"
)

// New creates a new MetalLB BGP speaker controller.
func New() *Speaker {
	logger := &bgplog.Logger{Entry: log}
	client := bgpk8s.New(logger.Logger)

	c, err := metallbspr.NewController(metallbspr.ControllerConfig{
		MyNode:        nodetypes.GetName(),
		Logger:        logger,
		SList:         nil, // BGP speaker doesn't use speakerlist
		DisableLayer2: true,
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize BGP speaker controller")
	}
	c.Client = client

	f, err := os.Open(option.Config.BGPConfigPath)
	if err != nil {
		log.WithError(err).Fatal("Failed to open BGP config file")
	}
	config, err := bgpconfig.Parse(f)
	if err != nil {
		log.WithError(err).Fatal("Failed to parse BGP configuration")
	}
	c.SetConfig(logger, config)

	spkr := &Speaker{
		Controller: c,

		logger:   logger,
		queue:    workqueue.New(),
		services: make(map[k8s.ServiceID]*slim_corev1.Service),
	}
	go spkr.run()

	log.Info("Started BGP speaker")

	return spkr
}

// Speaker represents the BGP speaker. It integrates Cilium's K8s events with
// MetalLB's logic for making BGP announcements. It is responsible for
// announcing BGP messages containing a loadbalancer IP address to peers.
type Speaker struct {
	*metallbspr.Controller

	logger *bgplog.Logger

	endpointsGetter endpointsGetter
	// queue holds all the events to process for the Speaker.
	queue workqueue.Interface

	lock.Mutex
	services map[k8s.ServiceID]*slim_corev1.Service
}

// OnUpdateService notifies the Speaker of an update to a service.
func (s *Speaker) OnUpdateService(svc *slim_corev1.Service) {
	svcID := k8s.ParseServiceID(svc)

	eps := new(metallbspr.Endpoints)
	epsFromSvc := s.endpointsGetter.GetEndpointsOfService(svcID)
	if epsFromSvc != nil {
		eps = convertInternalEndpoints(epsFromSvc)
	}

	s.Lock()
	s.services[svcID] = svc
	s.Unlock()

	s.queue.Add(epEvent{
		id:  svcID,
		svc: convertService(svc),
		eps: eps,
	})
}

// OnDeleteService notifies the Speaker of a delete of a service.
func (s *Speaker) OnDeleteService(svc *slim_corev1.Service) {
	svcID := k8s.ParseServiceID(svc)

	s.Lock()
	delete(s.services, svcID)
	s.Unlock()

	// Passing nil as the service will force the MetalLB speaker to withdraw
	// the BGP announcement.
	s.queue.Add(svcEvent{
		id:  svcID,
		svc: nil,
		eps: nil,
	})
}

// OnUpdateEndpoints notifies the Speaker of an update to the backends of a
// service.
func (s *Speaker) OnUpdateEndpoints(eps *slim_corev1.Endpoints) {
	svcID := k8s.ParseEndpointsID(eps)

	s.Lock()
	defer s.Unlock()
	if svc, ok := s.services[svcID]; ok {
		s.queue.Add(epEvent{
			id:  svcID,
			svc: convertService(svc),
			eps: convertEndpoints(eps),
		})
	}
}

// OnUpdateNode notifies the Speaker of an update to a node.
func (s *Speaker) OnUpdateNode(node *v1.Node) {
	s.queue.Add(nodeEvent(&node.Labels))
}

// RegisterSvcCache registers the K8s watcher cache with this Speaker.
func (s *Speaker) RegisterSvcCache(cache endpointsGetter) {
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
	for ip, be := range in.Backends {
		ep := metallbspr.Endpoint{
			IP:       ip,
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
