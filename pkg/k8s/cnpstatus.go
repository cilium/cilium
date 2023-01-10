// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/inctimer"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// CNPStatusEventHandler handles status updates events for all CNPs in the
// cluster. Upon creation of CNPs, it will start a controller for that CNP which
// handles sending of updates for that CNP to the Kubernetes API server. Upon
// receiving events from the key-value store, it will send the update for the
// CNP corresponding to the status update to the controller for that CNP.
type CNPStatusEventHandler struct {
	clientset      client.Clientset
	eventMap       *cnpEventMap
	cnpStore       *store.SharedStore
	k8sStore       cache.Store
	updateInterval time.Duration
}

// NodeStatusUpdater handles the lifecycle around sending CNP NodeStatus updates.
type NodeStatusUpdater struct {
	updateChan chan *NodeStatusUpdate
	stopChan   chan struct{}
}

type cnpEventMap struct {
	lock.RWMutex
	eventMap map[string]*NodeStatusUpdater
}

func newCNPEventMap() *cnpEventMap {
	return &cnpEventMap{
		eventMap: make(map[string]*NodeStatusUpdater),
	}
}

func (c *cnpEventMap) lookup(cnpKey string) (*NodeStatusUpdater, bool) {
	c.RLock()
	ch, ok := c.eventMap[cnpKey]
	c.RUnlock()
	return ch, ok
}

func (c *cnpEventMap) createIfNotExist(cnpKey string) (*NodeStatusUpdater, bool) {
	c.Lock()
	defer c.Unlock()
	nsu, ok := c.eventMap[cnpKey]
	// Cannot reinsert into map when active channel present.
	if ok {
		return nsu, ok
	}
	nsu = &NodeStatusUpdater{
		updateChan: make(chan *NodeStatusUpdate, 512),
		stopChan:   make(chan struct{}),
	}
	c.eventMap[cnpKey] = nsu
	return nsu, ok
}

func (c *cnpEventMap) delete(cnpKey string) {
	c.Lock()
	defer c.Unlock()
	nsu, ok := c.eventMap[cnpKey]
	if !ok {
		return
	}
	// Signal that we should stop processing events.
	close(nsu.stopChan)
	delete(c.eventMap, cnpKey)
}

// NewCNPStatusEventHandler returns a new CNPStatusEventHandler.
func NewCNPStatusEventHandler(clientset client.Clientset, k8sStore cache.Store, updateInterval time.Duration) *CNPStatusEventHandler {
	return &CNPStatusEventHandler{
		clientset:      clientset,
		eventMap:       newCNPEventMap(),
		k8sStore:       k8sStore,
		updateInterval: updateInterval,
	}
}

// NodeStatusUpdate pairs a CiliumNetworkPolicyNodeStatus to a specific node.
type NodeStatusUpdate struct {
	node string
	*cilium_v2.CiliumNetworkPolicyNodeStatus
}

// UpdateCNPStore updates the CNP store for the status event handler
// This must be called before before Starting the status handler using
// StartStatusHandler method.
func (c *CNPStatusEventHandler) UpdateCNPStore(cnpStore *store.SharedStore) {
	c.cnpStore = cnpStore
}

// OnDelete is called when a delete event is called on the CNP status key.
// It is a NoOp
func (c *CNPStatusEventHandler) OnDelete(_ store.NamedKey) {
	return
}

// OnUpdate is called when a CNPStatus object is modified in the KVStore.
func (c *CNPStatusEventHandler) OnUpdate(key store.Key) {
	cnpStatusUpdate, ok := key.(*CNPNSWithMeta)
	if !ok {
		log.WithFields(logrus.Fields{"kvstore-event": "update", "key": key.GetKeyName()}).
			Error("Not updating CNP Status; error converting key to CNPNSWithMeta")
		return
	}

	cnpKey := getKeyFromObject(cnpStatusUpdate)

	log.WithFields(logrus.Fields{
		"uid":       cnpStatusUpdate.UID,
		"name":      cnpStatusUpdate.Name,
		"namespace": cnpStatusUpdate.Namespace,
		"node":      cnpStatusUpdate.Node,
		"key":       cnpKey,
	}).Debug("received update event from kvstore")

	// Send the update to the corresponding controller for the
	// CNP which sends all status updates to the K8s apiserver.
	// If the namespace is empty for the status update then the cnpKey
	// will correspond to the ccnpKey.
	updater, ok := c.eventMap.lookup(cnpKey)
	if !ok {
		log.WithField("cnp", cnpKey).Debug("received event from kvstore for cnp for which we do not have any updater goroutine")
		return
	}
	nsu := &NodeStatusUpdate{node: cnpStatusUpdate.Node}
	nsu.CiliumNetworkPolicyNodeStatus = &(cnpStatusUpdate.CiliumNetworkPolicyNodeStatus)

	// Given that select is not deterministic, ensure that we check
	// for shutdown first. If not shut down, then try to send on
	// channel, or wait for shutdown so that we don't block forever
	// in case the channel is full and the updater is stopped.
	select {
	case <-updater.stopChan:
		// This goroutine is the only sender on this channel; we can
		// close safely if the stop channel is closed.
		close(updater.updateChan)

	default:
		select {
		// If the update is sent and we shut down after, the event
		// is 'lost'; we don't care because this means the CNP
		// was deleted anyway.
		case updater.updateChan <- nsu:
		case <-updater.stopChan:
			// This goroutine is the only sender on this channel; we can
			// close safely if the stop channel is closed.
			close(updater.updateChan)
		}
	}
}

// StopStatusHandler signals that we need to stop managing the sending of
// status updates to the Kubernetes APIServer for the given CNP. It also cleans
// up all status updates from the key-value store for this CNP.
func (c *CNPStatusEventHandler) StopStatusHandler(cnp *types.SlimCNP) {
	cnpKey := getKeyFromObject(cnp.GetObjectMeta())
	prefix := formatKeyForKvstore(cnp.GetObjectMeta())
	err := kvstore.Client().DeletePrefix(context.TODO(), prefix)
	if err != nil {
		log.WithError(err).WithField("prefix", prefix).Warning("error deleting prefix from kvstore")
	}
	c.eventMap.delete(cnpKey)
}

func (c *CNPStatusEventHandler) runStatusHandler(cnpKey string, cnp *types.SlimCNP, nodeStatusUpdater *NodeStatusUpdater) {
	namespace := cnp.Namespace
	name := cnp.Name
	nodeStatusMap := make(map[string]cilium_v2.CiliumNetworkPolicyNodeStatus)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNamespace:            namespace,
		logfields.CiliumNetworkPolicyName: name,
	})

	scopedLog.Debug("started status handler")

	// Iterate over the shared-store first. We may have received events for this
	// CNP in the key-value store from nodes which received and processed this
	// CNP and sent status updates for it before the watcher which updates this
	// `CNPStatusEventHandler` did. Given that we have the shared store which
	// caches all keys / values from the kvstore, we iterate and collect said
	// events. Given that this function is called after we have updated the
	// `eventMap` for this `CNPStatusEventHandler`, subsequent key updates from
	// the kvstore are guaranteed to be sent on the channel in the
	// `nodeStatusUpdater`, which we will receive in the for-loop below.
	sharedKeys := c.cnpStore.SharedKeysMap()
	for keyName, storeKey := range sharedKeys {
		// Look for any key which matches this CNP.
		if strings.HasPrefix(keyName, cnpKey) {
			cnpns, ok := storeKey.(*CNPNSWithMeta)
			if !ok {
				scopedLog.Errorf("received unexpected type mapping to key %s in cnp shared store: %T", keyName, storeKey)
				continue
			}
			// extract nodeName from keyName
			nodeStatusMap[cnpns.Node] = cnpns.CiliumNetworkPolicyNodeStatus
		}
	}
	updateTimer, updateDone := inctimer.New()
	defer updateDone()

	for {
		// Allow for a bunch of different node status updates to come before
		// we break out to avoid jitter in updates across the cluster
		// to affect batching on our end.
		limit := updateTimer.After(c.updateInterval)

		// Collect any other events that have come in, but bail out after the
		// above limit is hit so that we can send the updates we have received.
	Loop:
		for {
			select {
			case <-nodeStatusUpdater.stopChan:
				return
			case <-limit:
				if len(nodeStatusMap) == 0 {
					// If nothing to update, wait until we have something to update.
					limit = nil
					continue
				}
				break Loop
			case ev, ok := <-nodeStatusUpdater.updateChan:
				if !ok {
					return
				}
				nodeStatusMap[ev.node] = *ev.CiliumNetworkPolicyNodeStatus
				// If limit was set to nil then we can brake this
				// for loop as soon we have a CNPNS update from the kvstore.
				if limit == nil {
					break Loop
				}
			}
		}

		// Return if we received a request to stop in case we selected on the
		// limit being hit or receiving an update even if this goroutine was
		// stopped, as `select` is nondeterministic in which `case` it hits.
		select {
		case <-nodeStatusUpdater.stopChan:
			return
		default:
		}

		// Now that we have collected all events for
		// the given CNP, update the status for all nodes
		// which have sent us updates.
		if err := updateStatusesByCapabilities(c.clientset, namespace, name, nodeStatusMap); err != nil {
			scopedLog.WithError(err).Error("error updating status for CNP")
		}
	}
}

// StartStatusHandler starts the goroutine which sends status updates for the
// given CNP to the Kubernetes APIserver. If a status handler has already been
// started, it is a no-op.
func (c *CNPStatusEventHandler) StartStatusHandler(cnp *types.SlimCNP) {
	cnpKey := getKeyFromObject(cnp.GetObjectMeta())
	nodeStatusUpdater, ok := c.eventMap.createIfNotExist(cnpKey)
	if ok {
		return
	}
	go c.runStatusHandler(cnpKey, cnp, nodeStatusUpdater)
}

type K8sMetaObject interface {
	GetUID() k8sTypes.UID
	GetNamespace() string
	GetName() string
}

func getKeyFromObject(t K8sMetaObject) string {
	if ns := t.GetNamespace(); ns != "" {
		return path.Join(string(t.GetUID()), ns, t.GetName())
	}
	return path.Join(string(t.GetUID()), t.GetName())
}
