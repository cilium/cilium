// Copyright 2017-2018 Authors of Cilium
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

package workloads

import (
	ctx "context"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

type eventType string

const (
	// EventTypeStart represents when a workload was started
	EventTypeStart eventType = "start"
	// EventTypeDelete represents when a workload was deleted
	EventTypeDelete eventType = "delete"

	periodicSyncRate = 5 * time.Minute

	eventQueueBufferSize = 100
)

// EventMessage is the structure use for the different workload events.
type EventMessage struct {
	WorkloadID string
	EventType  eventType
}

// watcherState holds global close flag, per-container queues for events and
// ignore toggles
type watcherState struct {
	lock.Mutex

	events map[string]chan EventMessage
}

func newWatcherState() *watcherState {
	ws := &watcherState{
		events: make(map[string]chan EventMessage),
	}

	go func(state *watcherState) {
		for {
			// Clean up empty event handling channels
			state.reapEmpty()

			// periodically synchronize containers managed by the
			// local container runtime and checks if any of them
			// need to be managed by Cilium. This is a fall back
			// mechanism in case an event notification has been
			// lost.
			//
			// This is only required when *NOT* running in
			// Kubernetes mode as kubelet will keep containers and
			// pods in sync and will make CNI ADD and CNI DEL calls
			// as required.
			if !k8s.IsEnabled() {
				ws.syncWithRuntime()
			}

			time.Sleep(periodicSyncRate)
		}
	}(ws)

	return ws
}

// enqueueByContainerID starts a handler for this container, if needed, and
// enqueues a copy of the event if it is non-nil. Passing in a nil event will
// only start the handler. These handlers can be reaped via
// watcherState.reapEmpty.
// This parallelism is desirable to respond to events faster; each event might
// require talking to an outside daemon (docker) and a single noisy container
// might starve others.
func (ws *watcherState) enqueueByContainerID(containerID string, e *EventMessage) {
	ws.Lock()
	defer ws.Unlock()

	if _, found := ws.events[containerID]; !found {
		q := make(chan EventMessage, eventQueueBufferSize)
		ws.events[containerID] = q
		go Client().processEvents(q)
	}

	if e != nil {
		ws.events[containerID] <- *e
	}
}

// handlingContainerID returns whether there is a goroutine already consuming
// events for this id
func (ws *watcherState) handlingContainerID(id string) bool {
	ws.Lock()
	defer ws.Unlock()

	_, handled := ws.events[id]
	return handled
}

// reapEmpty deletes empty queues from the map. This also causes the handler
// goroutines to exit. It is expected to be called periodically to avoid the
// map growing over time.
func (ws *watcherState) reapEmpty() {
	ws.Lock()
	defer ws.Unlock()

	for id, q := range ws.events {
		if len(q) == 0 {
			close(q)
			delete(ws.events, id)
		}
	}
}

// syncWithRuntime is used by the daemon to synchronize changes between Docker and
// Cilium. This includes identities, labels, etc.
func (ws *watcherState) syncWithRuntime() {
	var wg sync.WaitGroup

	timeoutCtx, cancel := ctx.WithTimeout(ctx.Background(), 10*time.Second)
	defer cancel()

	cList, err := Client().workloadIDsList(timeoutCtx)
	if err != nil {
		log.WithError(err).Error("Failed to retrieve the container list")
		return
	}
	for _, contID := range cList {
		if ignoredContainer(contID) {
			continue
		}

		if alreadyHandled := ws.handlingContainerID(contID); !alreadyHandled {
			log.WithFields(logrus.Fields{
				logfields.ContainerID: shortContainerID(contID),
			}).Debug("Found unwatched container")

			wg.Add(1)
			go func(wg *sync.WaitGroup, id string) {
				defer wg.Done()
				Client().handleCreateWorkload(id, false)
			}(&wg, contID)
		}
	}

	// Wait for all spawned go routines handling container creations to exit
	wg.Wait()
}
