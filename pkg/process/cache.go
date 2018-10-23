// Copyright 2018 Authors of Cilium
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

package process

import (
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var (
	Cache = newCache()
)

type cache struct {
	mutex         lock.Mutex
	byPID         map[PID]*ProcessContext
	byContainerID map[string]*ProcessContext
}

func newCache() *cache {
	return &cache{
		byPID:         map[PID]*ProcessContext{},
		byContainerID: map[string]*ProcessContext{},
	}
}

func (c *cache) UpdateReferences(endpoint *endpoint.Endpoint) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	context, ok := c.byContainerID[endpoint.GetContainerID()]
	if ok {
		log.WithFields(logrus.Fields{
			logfields.ContainerID: endpoint.GetContainerID(),
		}).Debug("Updating process cache entry for endpoint")
		context.endpoint = endpoint
	} else {
		log.WithFields(logrus.Fields{
			logfields.ContainerID: endpoint.GetContainerID(),
		}).Warning("Couldn't find process cache entry for endpoint")
	}
}

func (c *cache) LookupOrCreate(pid PID) *ProcessContext {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	context, ok := c.byPID[pid]
	if !ok {
		context = newProcessContext(pid)
		c.byPID[pid] = context
		c.byContainerID[context.DockerContainerID] = context
	}

	return context
}

func (c *cache) Dump(writer io.Writer) {
	c.mutex.Lock()
	for _, p := range c.byPID {
		fmt.Fprintln(writer, p.String())
		for _, conn := range p.connections {
			fmt.Fprintf(writer, "  %s\n", conn.String())
		}
	}
	c.mutex.Unlock()
}

func (c *cache) Delete(pid PID) {
	c.mutex.Lock()
	context := c.byPID[pid]
	delete(c.byPID, pid)
	delete(c.byContainerID, context.DockerContainerID)
	c.mutex.Unlock()
}
