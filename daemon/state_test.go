// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/comparator"
	e "github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/workloads/containerd"

	. "gopkg.in/check.v1"
)

func createEndpoints() ([]*e.Endpoint, map[uint16]*e.Endpoint) {
	epsWanted := []*e.Endpoint{
		endpointCreator(256, policy.NumericIdentity(256)),
		endpointCreator(257, policy.NumericIdentity(256)),
		endpointCreator(258, policy.NumericIdentity(256)),
		endpointCreator(259, policy.NumericIdentity(256)),
	}
	epsMap := map[uint16]*e.Endpoint{
		epsWanted[0].ID: epsWanted[0],
		epsWanted[1].ID: epsWanted[1],
		epsWanted[2].ID: epsWanted[2],
		epsWanted[3].ID: epsWanted[3],
	}
	return epsWanted, epsMap
}

func getStrID(id uint16) string {
	return fmt.Sprintf("%05d", id)
}

func endpointCreator(id uint16, secID policy.NumericIdentity) *e.Endpoint {
	strID := getStrID(id)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, id)
	ep := &e.Endpoint{
		ID:       id,
		DockerID: "",
		// Random network ID and docker endpoint ID with 59 hex chars + 5 strID = 64 hex chars
		DockerNetworkID:  "603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def001" + strID,
		DockerEndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d8002" + strID,
		IfName:           "lxc" + strID,
		LXCMAC:           mac.MAC([]byte{0x01, 0xff, 0xf2, 0x12, b[0], b[1]}),
		IPv4:             addressing.DeriveCiliumIPv4(net.IP{0xc0, 0xa8, b[0], b[1]}),
		IPv6:             addressing.DeriveCiliumIPv6(net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, b[0], b[1]}),
		IfIndex:          1,
		NodeMAC:          mac.MAC([]byte{0x02, 0xff, 0xf2, 0x12, 0x0, 0x0}),
		SecLabel: &policy.Identity{
			ID: secID,
			Labels: labels.Labels{
				"foo" + strID: labels.NewLabel("foo"+strID, "", ""),
			},
		},
		PortMap: nil,
		Consumable: &policy.Consumable{
			ID:        secID,
			Iteration: 0,
			Labels: &policy.Identity{
				ID: secID,
				Labels: labels.Labels{
					"foo" + strID: labels.NewLabel("foo"+strID, "", ""),
				},
			},
			Maps:         map[int]*policymap.PolicyMap{},
			Consumers:    map[string]*policy.Consumer{},
			ReverseRules: map[policy.NumericIdentity]*policy.Consumer{},
		},
	}
	ep.SetDefaultOpts(nil)
	ep.Status = e.NewEndpointStatus()
	return ep
}

// generateEPs is a helper function to create dummy endpoints in the given
// baseDirectory. This function regenerates the endpoints and creates the bpf
// and header files in the endpoint's directory
func (ds *DaemonSuite) generateEPs(baseDir string, epsWanted []*e.Endpoint, epsMap map[uint16]*e.Endpoint) ([]string, error) {
	var err error
	defer func() {
		if err != nil {
			os.RemoveAll(baseDir)
		}
	}()

	ds.d.compilationMutex = new(lock.RWMutex)

	ds.OnGetStateDir = func() string {
		return baseDir
	}
	ds.OnQueueEndpointBuild = func(r *e.Request) {
		go func(*e.Request) {
			r.MyTurn <- true
			<-r.Done
		}(r)
	}
	ds.OnGetCachedMaxLabelID = func() (policy.NumericIdentity, error) {
		return policy.NumericIdentity(259), nil
	}
	ds.OnTracingEnabled = func() bool {
		return false
	}
	ds.OnGetPolicyRepository = func() *policy.Repository {
		return policy.NewPolicyRepository()
	}
	ds.OnAlwaysAllowLocalhost = func() bool {
		return false
	}
	ds.OnEnableEndpointPolicyEnforcement = func(e *e.Endpoint) bool {
		return true
	}
	ds.OnDryModeEnabled = func() bool {
		return true
	}

	ds.OnGetCompilationLock = func() *lock.RWMutex {
		return ds.d.compilationMutex
	}

	ds.OnGetCachedLabelList = func(id policy.NumericIdentity) (labels.LabelArray, error) {
		if c := policy.GetConsumableCache().Lookup(id); c != nil {
			return c.LabelArray, nil
		}
		return nil, nil
	}

	// Since all owner's funcs are implemented we can regenerate every endpoint.
	epsNames := []string{}
	for _, ep := range epsWanted {
		os.MkdirAll(filepath.Join(baseDir, ep.StringID()), 777)
		<-ep.Regenerate(ds)
		epsNames = append(epsNames, ep.StringID())
	}
	return epsNames, nil
}

func (ds *DaemonSuite) TestReadEPsFromDirNames(c *C) {
	epsWanted, epsMap := createEndpoints()
	tmpDir, err := ioutil.TempDir("", "cilium-tests")
	defer func() {
		os.RemoveAll(tmpDir)
	}()
	c.Assert(err, IsNil)
	epsNames, err := ds.generateEPs(tmpDir, epsWanted, epsMap)
	c.Assert(err, IsNil)
	eps := readEPsFromDirNames(tmpDir, epsNames)
	c.Assert(len(eps), Equals, len(epsWanted))
}

func (ds *DaemonSuite) TestCleanUpDockerDangling(c *C) {
	epsWanted, epsMap := createEndpoints()

	err := containerd.InitMock()
	c.Assert(err, IsNil)

	for _, ep := range epsWanted {
		endpointmanager.Insert(ep)
	}

	ep, err := endpointmanager.Lookup(e.NewCiliumID(259))
	c.Assert(err, IsNil)
	c.Assert(ep, comparator.DeepEquals, epsMap[259])

	ds.d.deleteNonFunctionalEndpoints()

	// Since 259 doesn't exist in the list of docker network endpoint running,
	// it will be removed from the list of endpoints

	ep, err = endpointmanager.Lookup(e.NewCiliumID(259))
	c.Assert(err, IsNil)
	c.Assert(ep, IsNil)
}

func (ds *DaemonSuite) TestSyncLabels(c *C) {
	epsWanted, _ := createEndpoints()

	ep1 := epsWanted[0]
	ep1.SecLabel = nil
	err := ds.d.syncLabels(ep1)
	// Endpoint doesn't have a security label, syncLabels should not sync
	// anything.
	c.Assert(err, Not(IsNil))

	// Let's make sure we delete all labels from the kv store first
	ep2 := epsWanted[1]
	ep2id := ep2.StringID()
	ep2SecLabelID := ep2.SecLabel.ID
	hash := ep2.SecLabel.Labels.SHA256Sum()
	ds.d.DeleteIdentityBySHA256(hash, ep2id)

	err = ds.d.syncLabels(ep2)
	c.Assert(err, IsNil)
	// The SecLabel ID should not have been changed
	c.Assert(ep2SecLabelID, Equals, ep2.SecLabel.ID)

	// let's change the ep2 sec label ID and see if sync labels properly sets
	// it with the one from kv store
	ep2.SecLabel.ID = policy.NumericIdentity(1)

	err = ds.d.syncLabels(ep2)
	c.Assert(err, IsNil)
	// The SecLabel ID should have been changed with the one stored in the
	// kv store
	c.Assert(ep2SecLabelID, Equals, ep2.SecLabel.ID)
}
