// Copyright 2016-2019 Authors of Cilium
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

// +build !privileged_tests

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/completion"
	linuxDatapath "github.com/cilium/cilium/pkg/datapath/linux"
	e "github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"

	. "gopkg.in/check.v1"
)

func createEndpoints() ([]*e.Endpoint, map[uint16]*e.Endpoint) {
	epsWanted := []*e.Endpoint{
		endpointCreator(256, identity.NumericIdentity(256)),
		endpointCreator(257, identity.NumericIdentity(256)),
		endpointCreator(258, identity.NumericIdentity(256)),
		endpointCreator(259, identity.NumericIdentity(256)),
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

func endpointCreator(id uint16, secID identity.NumericIdentity) *e.Endpoint {
	strID := getStrID(id)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, id)

	ep := e.NewEndpointWithState(id, e.StateReady)
	// Random network ID and docker endpoint ID with 59 hex chars + 5 strID = 64 hex chars
	ep.DockerNetworkID = "603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def001" + strID
	ep.DockerEndpointID = "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d8002" + strID
	ep.IfName = "lxc" + strID
	ep.LXCMAC = mac.MAC([]byte{0x01, 0xff, 0xf2, 0x12, b[0], b[1]})
	ep.IPv4 = addressing.DeriveCiliumIPv4(net.IP{0xc0, 0xa8, b[0], b[1]})
	ep.IPv6 = addressing.DeriveCiliumIPv6(net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, b[0], b[1]})
	ep.IfIndex = 1
	ep.SetNodeMACLocked(mac.MAC([]byte{0x02, 0xff, 0xf2, 0x12, 0x0, 0x0}))
	ep.SecurityIdentity = &identity.Identity{
		ID: secID,
		Labels: labels.Labels{
			"foo" + strID: labels.NewLabel("foo"+strID, "", ""),
		},
	}
	ep.OpLabels = labels.NewOpLabels()
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

	builders := 0
	defer func() {
		if builders != 0 {
			log.Fatal("Endpoint Build Queue leaks")
		}
	}()

	ds.OnQueueEndpointBuild = func(ctx context.Context, epID uint64) (func(), error) {
		builders++
		var once sync.Once
		doneFunc := func() {
			once.Do(func() {
				builders--
			})
		}
		return doneFunc, nil
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

	ds.OnGetCompilationLock = func() *lock.RWMutex {
		return ds.d.compilationMutex
	}

	ds.OnSendNotification = func(typ monitorAPI.AgentNotification, text string) error {
		return nil
	}

	ds.OnUpdateNetworkPolicy = func(e *e.Endpoint, policy *policy.L4Policy,
		labelsMap cache.IdentityCache, proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
		return nil, nil
	}

	ds.OnRemoveNetworkPolicy = func(e *e.Endpoint) {}

	// Since all owner's funcs are implemented we can regenerate every endpoint.
	epsNames := []string{}
	for _, ep := range epsWanted {
		fullDirName := filepath.Join(baseDir, ep.DirectoryPath())
		os.MkdirAll(fullDirName, 777)
		ep.UnconditionalLock()

		// The identities must be tracked in identitymanager to
		// regenerate the policy for them.
		identitymanager.Add(ep.SecurityIdentity)
		defer identitymanager.Remove(ep.SecurityIdentity)

		ready := ep.SetStateLocked(e.StateWaitingToRegenerate, "test")
		ep.Unlock()
		if ready {
			<-ep.Regenerate(ds, regenerationMetadata)
		}

		switch ep.ID {
		case 256, 257:
			err := os.Rename(fullDirName, filepath.Join(baseDir, ep.FailedDirectoryPath()))
			if err != nil {
				return nil, err
			}
			epsNames = append(epsNames, ep.FailedDirectoryPath())

			// create one failed and the other non failed directory for ep 256.
			if ep.ID == 256 {
				fullDirName := filepath.Join(baseDir, ep.DirectoryPath())
				os.MkdirAll(fullDirName, 777)

				ep.UnconditionalLock()
				// Change endpoint a little bit so we know which endpoint is in
				// "256_next_fail" and with one is in the "256" directory.
				ep.SetNodeMACLocked(mac.MAC([]byte{0x02, 0xff, 0xf2, 0x12, 0xc1, 0xc1}))
				ready := ep.SetStateLocked(e.StateWaitingToRegenerate, "test")
				ep.Unlock()
				if ready {
					<-ep.Regenerate(ds, regenerationMetadata)
				}
				epsNames = append(epsNames, ep.DirectoryPath())
			}
		default:
			epsNames = append(epsNames, ep.DirectoryPath())
		}
	}
	return epsNames, nil
}

func (ds *DaemonSuite) TestReadEPsFromDirNames(c *C) {
	// For this test, the real linux datapath is necessary to properly
	// serialize config files to disk and test the restore.
	oldDatapath := ds.d.datapath
	defer func() {
		ds.d.datapath = oldDatapath
	}()
	ds.d.datapath = linuxDatapath.NewDatapath(linuxDatapath.DatapathConfiguration{})

	epsWanted, epsMap := createEndpoints()
	tmpDir, err := ioutil.TempDir("", "cilium-tests")
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	os.Chdir(tmpDir)

	oldStateDir := option.Config.StateDir
	option.Config.StateDir = tmpDir
	defer func() {
		os.Chdir(oldStateDir)
		option.Config.StateDir = oldStateDir
	}()
	c.Assert(err, IsNil)
	epsNames, err := ds.generateEPs(tmpDir, epsWanted, epsMap)
	c.Assert(err, IsNil)
	eps := e.ReadEPsFromDirNames(tmpDir, epsNames)
	c.Assert(len(eps), Equals, len(epsWanted))

	e.OrderEndpointAsc(epsWanted)
	var restoredEPs []*e.Endpoint
	for _, ep := range eps {
		restoredEPs = append(restoredEPs, ep)
	}
	e.OrderEndpointAsc(restoredEPs)

	c.Assert(len(restoredEPs), Equals, len(epsWanted))
	for i, restoredEP := range restoredEPs {
		// We probably shouldn't modify these, but the status will
		// naturally differ between the wanted endpoint and the version
		// that's restored, because the restored version has log
		// messages relating to the restore.
		restoredEP.Status = nil
		wanted := epsWanted[i]
		wanted.Status = nil
		c.Assert(restoredEP.String(), checker.DeepEquals, wanted.String())
	}
}
