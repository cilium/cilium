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

package proxylib

import (
	"fmt"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/npds"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

type Instance struct {
	id            uint64
	accessLogPath string
	accessLogger  *accesslog.Client
	xdsPath       string
	policyClient  *npds.Client
	nodeId        string
	openCount     uint64

	policyMap atomic.Value // holds PolicyMap
}

var (
	// mutex protects instances
	mutex lock.RWMutex
	// Key uint64 is a monotonically increasing instance ID
	instances map[uint64]*Instance = make(map[uint64]*Instance)
	// Last instance ID used
	instanceId uint64 = 0
)

// OpenInstance creates a new instance or finds an existing one with equivalent parameters.
// returns the instance id.
func OpenInstance(xdsPath, accessLogPath string) uint64 {
	mutex.Lock()
	defer mutex.Unlock()

	// Check if have an instance with these params already
	for id, old := range instances {
		if old.xdsPath == xdsPath && old.accessLogPath == accessLogPath {
			old.openCount++
			log.Infof("Opened existing library instance %d, open count: %d", id, old.openCount)
			return id
		}
	}

	instanceId++

	// TODO: Sidecar instance id needs to be different.
	new := &Instance{
		id:            instanceId,
		accessLogPath: accessLogPath,
		xdsPath:       xdsPath,
		nodeId:        fmt.Sprintf("host~127.0.0.1~libcilium-%d~localdomain", instanceId),
		openCount:     1,
	}

	new.setPolicyMap(newPolicyMap())
	if new.xdsPath != "" {
		new.policyClient = npds.NewClient(new.xdsPath, new.nodeId, new)
	}
	if new.accessLogPath != "" {
		new.accessLogger = accesslog.NewClient(new.accessLogPath)
	}

	instances[instanceId] = new

	log.Infof("Opened new library instance %d", instanceId)

	return instanceId
}

func FindInstance(id uint64) *Instance {
	mutex.RLock()
	defer mutex.RUnlock()
	return instances[id]
}

// Close returns the new open count
func CloseInstance(id uint64) uint64 {
	mutex.Lock()
	defer mutex.Unlock()

	count := uint64(0)
	if ins, ok := instances[id]; ok {
		ins.openCount--
		count = ins.openCount
		if count <= 0 {
			if ins.policyClient != nil {
				ins.policyClient.Close()
			}
			if ins.accessLogger != nil {
				ins.accessLogger.Close()
			}
			delete(instances, id)
		}
		log.Infof("CloseInstance(%d): Remaining open count: %d", id, count)
	} else {
		log.Infof("CloseInstance(%d): Not found (closed already?)", id)
	}
	return count
}

func (ins *Instance) getPolicyMap() PolicyMap {
	return ins.policyMap.Load().(PolicyMap)
}

func (ins *Instance) setPolicyMap(newMap PolicyMap) {
	ins.policyMap.Store(newMap)
}

func (ins *Instance) PolicyMatches(endpointPolicyName string, ingress bool, port, remoteId uint32, l7 interface{}) bool {
	// Policy maps are never modified once published
	policy, found := ins.getPolicyMap()[endpointPolicyName]
	if !found {
		log.Debugf("NPDS: Policy for %s not found (%v)", endpointPolicyName)
	}

	return found && policy.Matches(ingress, port, remoteId, l7)
}

// Update the PolicyMap from a protobuf. PolicyMap is only ever changed if the whole update is successful.
func (ins *Instance) PolicyUpdate(resp *envoy_api_v2.DiscoveryResponse) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(error); !ok {
				err = fmt.Errorf("NPDS: Panic: %v", r)
			}
		}
	}()

	log.Debugf("NPDS: Updating policy from %v", resp)

	oldMap := ins.getPolicyMap()
	newMap := newPolicyMap()

	for _, any := range resp.Resources {
		if any.TypeUrl != resp.TypeUrl {
			return fmt.Errorf("NPDS: Mismatching TypeUrls: %s != %s", any.TypeUrl, resp.TypeUrl)
		}
		var config cilium.NetworkPolicy
		if err = proto.Unmarshal(any.Value, &config); err != nil {
			return fmt.Errorf("NPDS: Policy unmarshal error: %v", err)
		}

		policyName := config.GetName()

		// Locate the old version, if any
		oldPolicy, found := oldMap[policyName]
		if found {
			// Check if the new policy is the same as the old one
			if proto.Equal(&config, &oldPolicy.protobuf) {
				log.Debugf("NPDS: New policy for %s is equal to the old one, no need to change", policyName)
				newMap[policyName] = oldPolicy
				continue
			}
		}

		// Validate new config
		if err = config.Validate(); err != nil {
			return fmt.Errorf("NPDS: Policy validation error for %s: %v", policyName, err)
		}

		// Create new PolicyInstance, may panic
		newMap[policyName] = newPolicyInstance(&config)
	}

	// Store the new policy map
	ins.setPolicyMap(newMap)

	log.Debugf("NPDS: Policy Update completed for instance %d: %v", ins.id, newMap)
	return
}

func (ins *Instance) Log(pblog *cilium.LogEntry) {
	ins.accessLogger.Log(pblog)
}
