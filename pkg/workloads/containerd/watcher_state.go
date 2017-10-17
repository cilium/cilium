// Copyright 2017 Authors of Cilium
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

package containerd

import (
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"

	dTypes "github.com/docker/engine-api/types"
	dTypesEvents "github.com/docker/engine-api/types/events"
	"github.com/sirupsen/logrus"
	ctx "golang.org/x/net/context"
)

// watcherState holds global close flag, per-container queues for events and
// ignore toggles
type watcherState struct {
	lock.Mutex

	eventQueueBufferSize int
	events               map[string]chan dTypesEvents.Message
}

func newWatcherState(eventQueueBufferSize int) *watcherState {
	return &watcherState{
		eventQueueBufferSize: eventQueueBufferSize,
		events:               make(map[string]chan dTypesEvents.Message),
	}
}

// enqueueByContainerID starts a handler for this container, if needed, and
// enqueues a copy of the event if it is non-nil. Passing in a nil event will
// only start the handler. These handlers can be reaped via
// watcherState.reapEmpty.
// This parallelism is desirable to respond to events faster; each event might
// require talking to an outside daemon (docker) and a single noisy container
// might starve others.
func (ws *watcherState) enqueueByContainerID(containerID string, e *dTypesEvents.Message) {
	ws.Lock()
	defer ws.Unlock()

	if _, found := ws.events[containerID]; !found {
		q := make(chan dTypesEvents.Message, eventQueueBufferSize)
		ws.events[containerID] = q
		go processContainerEvents(q)
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

	cList, err := dockerClient.ContainerList(ctx.Background(), dTypes.ContainerListOptions{All: false})
	if err != nil {
		log.WithError(err).Error("Failed to retrieve the container list")
		return
	}
	for _, cont := range cList {
		if ignoredContainer(cont.ID) {
			continue
		}

		if alreadyHandled := ws.handlingContainerID(cont.ID); !alreadyHandled {
			log.WithFields(logrus.Fields{
				logfields.ContainerID: shortContainerID(cont.ID),
			}).Debug("Found unwatched container")

			wg.Add(1)
			go func(wg *sync.WaitGroup, id string) {
				defer wg.Done()
				ws.enqueueByContainerID(id, nil) // ensure a handler is running for future events
				handleCreateContainer(id, false)
			}(&wg, cont.ID)
		}
	}

	// Wait for all spawned go routines handling container creations to exit
	wg.Wait()
}
