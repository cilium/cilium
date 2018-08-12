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

	"github.com/cilium/cilium/pkg/lock"
)

var (
	Cache = newCache()
)

type cache struct {
	mutex lock.Mutex
	pids  map[PID]*ProcessContext
}

func newCache() *cache {
	return &cache{
		pids: map[PID]*ProcessContext{},
	}
}

func (c *cache) LookupOrCreate(pid PID) *ProcessContext {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	context, ok := c.pids[pid]
	if !ok {
		context = newProcessContext(pid)
		c.pids[pid] = context
	}

	return context
}

func (c *cache) Dump(writer io.Writer) {
	c.mutex.Lock()
	for _, p := range c.pids {
		fmt.Fprintln(writer, p.String())
		for _, conn := range p.connections {
			fmt.Fprintf(writer, "  %s\n", conn.String())
		}
	}
	c.mutex.Unlock()
}

func (c *cache) Delete(pid PID) {
	c.mutex.Lock()
	delete(c.pids, pid)
	c.mutex.Unlock()
}
