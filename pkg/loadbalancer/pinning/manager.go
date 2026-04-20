// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pinning

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

type PinningParams struct {
	cell.In
	JobGroup           job.Group
	Logger             *slog.Logger
	Services           resource.Resource[*slim_corev1.Service]
	Nodes              resource.Resource[*slim_corev1.Node]
	LocalNodeStore     *node.LocalNodeStore
	LBMaps             lbmaps.LBMaps
	PinMapUpdateStream *lbPinMapEventStream
}

type PinningManager struct {
	logger                  *slog.Logger
	jobGroup                job.Group
	services                resource.Resource[*slim_corev1.Service]
	nodes                   resource.Resource[*slim_corev1.Node]
	localNodeStore          *node.LocalNodeStore
	lBMaps                  lbmaps.LBMaps
	reconcileChannel        chan reconcileUpdate
	nodesCache              nodesMap
	servicesCache           servicesMap
	nodesSynced             bool
	servicesSynced          bool
	pinMapUpdateEventStream *lbPinMapEventStream
}

func newPinningManager(params PinningParams) *PinningManager {
	return &PinningManager{
		logger:                  params.Logger,
		jobGroup:                params.JobGroup,
		services:                params.Services,
		nodes:                   params.Nodes,
		lBMaps:                  params.LBMaps,
		localNodeStore:          params.LocalNodeStore,
		reconcileChannel:        make(chan reconcileUpdate),
		nodesCache:              nodesMap{},
		servicesCache:           servicesMap{},
		nodesSynced:             false,
		servicesSynced:          false,
		pinMapUpdateEventStream: params.PinMapUpdateStream,
	}
}

func parsePinnedService(svc *slim_corev1.Service) string {
	nodeName, pinned := svc.Annotations[annotation.ServicePinningNode]

	if pinned {
		return nodeName
	}

	return ""
}

func (pm *PinningManager) handleServiceEvent(ctx context.Context, event resource.Event[*slim_corev1.Service]) error {
	var msg reconcileUpdate

	switch event.Kind {
	case resource.Sync:
		msg = syncService{}
	case resource.Delete, resource.Upsert:
		nodeName := parsePinnedService(event.Object)

		if nodeName == "" {
			return eventDone(event, nil)
		}

		if len(event.Object.Spec.ExternalIPs) > 0 {
			serviceIp, err := netip.ParseAddr(event.Object.Spec.ExternalIPs[0])

			if err != nil {
				return eventDone(event, err)
			}

			serviceId := event.Object.Name

			if event.Kind == resource.Upsert {
				msg = addService{pinnedService{
					ServiceId: serviceId,
					ServiceIp: serviceIp,
					NodeId:    nodeName,
				}}
			} else {
				msg = deleteService{pinnedService{
					ServiceId: serviceId,
					ServiceIp: serviceIp,
					NodeId:    nodeName,
				}}
			}
		}
	}

	event.Done(nil)
	pm.reconcileChannel <- msg

	return nil
}

func isNodeReady(node *slim_corev1.Node) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type == slim_corev1.NodeReady && cond.Status == slim_corev1.ConditionTrue {
			return true
		}
	}

	return false
}

func parseNodeIp(nodeName string, nodeAddresses []slim_corev1.NodeAddress) (*netip.Addr, error) {
	nodeIp := ""

	for _, a := range nodeAddresses {
		if a.Type == slim_corev1.NodeInternalIP {
			addr, err := netip.ParseAddr(a.Address)

			if err != nil {
				return nil, err
			}

			if addr.Is4() {
				nodeIp = addr.String()
				break
			}
		}
	}

	if nodeIp == "" {
		return nil, fmt.Errorf("IP has not found for %s %s", logfields.NodeName, nodeName)
	}

	ip, err := netip.ParseAddr(nodeIp)

	if err != nil {
		return nil, err
	}

	return &ip, nil
}

func (pm *PinningManager) handleNodeEvent(ctx context.Context, event resource.Event[*slim_corev1.Node]) error {
	var msg reconcileUpdate

	switch event.Kind {
	case resource.Sync:
		msg = syncNode{}
	case resource.Upsert, resource.Delete:
		nodeIp, err := parseNodeIp(event.Key.Name, event.Object.Status.Addresses)

		if err != nil {
			pm.logger.Error(err.Error())
			return eventDone(event, nil)
		}

		nodeName := event.Object.Name

		if event.Kind == resource.Upsert && isNodeReady(event.Object) {
			msg = addNode{nodeToPin{
				NodeName: nodeName,
				NodeIp:   *nodeIp,
			}}
		} else {
			msg = deleteNode{nodeToPin{
				NodeName: nodeName,
				NodeIp:   *nodeIp,
			}}
		}
	}

	event.Done(nil)
	pm.reconcileChannel <- msg

	return nil
}

func (pm *PinningManager) applyPinningMap(desired PinningMap) error {
	stale, err := DumpPinningMap(pm.lBMaps)

	if err != nil {
		return err
	}

	for k, v := range desired {
		if err := pm.lBMaps.UpdatePinning4(&k, &v); err != nil {
			return err
		}

		delete(stale, k)
	}

	for k := range stale {
		if err := pm.lBMaps.DeletePinning4(&k); err != nil {
			return err
		}
	}

	return nil
}

func rebalanceServices(
	services servicesMap,
	nodes nodesMap,
) (PinningMap, error) {
	newPinningMap := PinningMap{}

	for _, svc := range services {
		nodeIp, found := nodes[svc.NodeId]

		if !found {
			continue
		}

		k := maps.LbPinning4Key{ServiceIP: iPv4FromAddr(svc.ServiceIp)}
		v := maps.LbPinning4Value{NodeIP: iPv4FromAddr(nodeIp)}

		newPinningMap[k] = v
	}

	return newPinningMap, nil
}

func (pm *PinningManager) reconcileLoop(ctx context.Context, health cell.Health) error {
	localNode, err := pm.localNodeStore.Get(ctx)

	if err != nil {
		return err
	}

	defer pm.pinMapUpdateEventStream.complete(err)

	if len(localNode.IPAddresses) == 0 {
		pm.logger.Info(fmt.Sprintf("node '%s' has no assigned IP addresses, exiting pinning manager reconcile loop", localNode.Name))
		return nil
	}

	nodeIp := localNode.GetNodeInternalIPv4().To4()

	if nodeIp == nil {
		return fmt.Errorf("node '%s' has no assigned IP address", localNode.Name)
	}

	pm.jobGroup.Add(job.Observer(
		"pinning-service-observer",
		pm.handleServiceEvent,
		pm.services,
	))

	pm.jobGroup.Add(job.Observer(
		"pinning-node-observer",
		pm.handleNodeEvent,
		pm.nodes,
	))

	localNodeIp, _ := netip.AddrFromSlice(nodeIp)

	for {
		select {
		case event := <-pm.reconcileChannel:
			switch msg := event.(type) {
			case addNode:
				pm.nodesCache[msg.NodeName] = msg.NodeIp
			case deleteNode:
				delete(pm.nodesCache, msg.NodeName)

			case addService:
				pm.servicesCache[msg.ServiceId] = msg.pinnedService
			case deleteService:
				delete(pm.servicesCache, msg.ServiceId)

			case syncService:
				pm.servicesSynced = true
			case syncNode:
				pm.nodesSynced = true
			}

			if !pm.nodesSynced || !pm.servicesSynced {
				continue
			}

			fullPinningMap, err := rebalanceServices(
				pm.servicesCache,
				pm.nodesCache,
			)

			if err != nil {
				pm.logger.Error("error making desired pinning map", logfields.Error, err)
				continue
			}

			nodeSpecificPinningMap := PinningMap{}

			for k, v := range fullPinningMap {
				if v.NodeIP.Addr() != localNodeIp {
					nodeSpecificPinningMap[k] = v
				}
			}

			if err := pm.applyPinningMap(nodeSpecificPinningMap); err != nil {
				pm.logger.Error("error applying desired pinning map", logfields.Error, err)
				continue
			}

			pm.pinMapUpdateEventStream.emitter(LbPinMapUpdateEvent{PinningMap: fullPinningMap})

		case <-ctx.Done():
			// graceful shutdown
			pm.pinMapUpdateEventStream.complete(nil)
			return nil
		}
	}
}

func registerPinningManager(params PinningParams) (*PinningManager, error) {
	mng := newPinningManager(params)

	params.JobGroup.Add(job.OneShot(
		"pinning-reconciler-loop",
		mng.reconcileLoop,
	))

	return mng, nil
}
