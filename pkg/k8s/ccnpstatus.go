// Copyright 2019-2020 Authors of Cilium
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

package k8s

import (
	"context"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"

	"k8s.io/client-go/tools/cache"
)

var CCNPStatusesPath = path.Join(kvstore.BaseKeyPrefix, "state", "ccnpstatuses", "v2")

// CCNPStatusEventHandler handles status updates events for all the CCNPs
// in the cluster. Upon creation of Clusterwide policies, it will start a
// controller for that CNP which handles sending of updates for that CCNP to
// the kubernetes API server. Upon receiving eventes from the key-value store
// it will send the update for the CCNP corresponding to the status update to
// the controller for that CCNP.
type CCNPStatusEventHandler struct {
	*CNPStatusEventHandler
}

// NewCCNPStatusEventHandler returns a new CCNPStatusEventHandler.
// which is more or less a wrapper around the CNPStatusEventHandler itself.
func NewCCNPStatusEventHandler(cnpStore *store.SharedStore, k8sStore cache.Store, updateInterval time.Duration) *CCNPStatusEventHandler {
	return &CCNPStatusEventHandler{
		CNPStatusEventHandler: NewCNPStatusEventHandler(cnpStore, k8sStore, updateInterval),
	}
}

// WatchForCCNPStatusEvents starts a watcher for all the Clusterwide policy
// updates from the key-value store.
func (c *CCNPStatusEventHandler) WatchForCCNPStatusEvents() {
	watcher := kvstore.Client().ListAndWatch(context.TODO(), "ccnpStatusWatcher", CCNPStatusesPath, 512)

	// Loop and block for this network policy watch event.
	for {
		c.watchForCNPStatusEvents(watcher)
	}
}
