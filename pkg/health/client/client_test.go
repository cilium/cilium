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

// +build !privileged_tests

package client

import (
	"io/ioutil"
	"testing"

	"github.com/cilium/cilium/api/v1/health/models"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ClientTestSuite struct{}

var _ = Suite(&ClientTestSuite{})

func (s *ClientTestSuite) TestFormatNodeStatus(c *C) {
	// This test generates permutations of models.NodeStatus and sees whether
	// the calls to formatNodeStatus panic; the result of this test being
	// successful is whether the test does not panic.

	// not testing output, just that permutations of NodeStatus don't cause
	// panics.
	w := ioutil.Discard

	connectivityStatusGood := &models.ConnectivityStatus{
		Latency: 1,
		Status:  "",
	}
	connectivityStatusBad := &models.ConnectivityStatus{
		Latency: 1,
		Status:  "bad status",
	}
	possibleConnectivityStatus := []*models.ConnectivityStatus{
		connectivityStatusBad,
		connectivityStatusGood,
	}
	possibleIPs := []string{"192.168.1.1", ""}

	possibleNames := []string{"node1", ""}

	possiblePathStatuses := []*models.PathStatus{}

	for _, connectivityStatusHTTP := range possibleConnectivityStatus {
		for _, connectivityStatusICMP := range possibleConnectivityStatus {
			for _, possibleIP := range possibleIPs {
				pathStatus := &models.PathStatus{
					HTTP: connectivityStatusHTTP,
					Icmp: connectivityStatusICMP,
					IP:   possibleIP,
				}
				possiblePathStatuses = append(possiblePathStatuses, pathStatus)
			}
		}
	}

	possibleSecondaryAddresses := make([]*models.PathStatus, 0, len(possiblePathStatuses)+1)
	possibleSecondaryAddresses = append(possibleSecondaryAddresses, nil)
	possibleSecondaryAddresses = append(possibleSecondaryAddresses, possiblePathStatuses...)

	// Assemble possible host statuses.
	possibleHostStatuses := []*models.HostStatus{
		nil,
	}

	for _, possiblePrimaryAddress := range possiblePathStatuses {
		hostStatus := &models.HostStatus{
			PrimaryAddress:     possiblePrimaryAddress,
			SecondaryAddresses: possibleSecondaryAddresses,
		}
		possibleHostStatuses = append(possibleHostStatuses, hostStatus)
	}

	printAllOptions := []bool{true, false}
	succinctOptions := []bool{true, false}
	verboseOptions := []bool{true, false}
	localhostOptions := []bool{true, false}

	for _, possibleEndpointStatus := range possiblePathStatuses {
		for _, hostStatus := range possibleHostStatuses {
			for _, name := range possibleNames {
				ns := &models.NodeStatus{
					Endpoint: possibleEndpointStatus,
					Host:     hostStatus,
					Name:     name,
				}
				for _, printAllOpt := range printAllOptions {
					for _, succintOpt := range succinctOptions {
						for _, verboseOpt := range verboseOptions {
							for _, localhostOpt := range localhostOptions {
								formatNodeStatus(w, ns, printAllOpt, succintOpt, verboseOpt, localhostOpt)
							}
						}
					}
				}
			}
		}
	}
}

func (s *ClientTestSuite) TestGetHostPrimaryAddress(c *C) {
	nilHostNS := &models.NodeStatus{
		Host: nil,
	}

	pathStatus := GetHostPrimaryAddress(nilHostNS)
	c.Assert(pathStatus, IsNil)

	nilPrimaryAddressNS := &models.NodeStatus{
		Host: &models.HostStatus{
			PrimaryAddress: nil,
		},
	}

	pathStatus = GetHostPrimaryAddress(nilPrimaryAddressNS)
	c.Assert(pathStatus, IsNil)

	primaryAddressNS := &models.NodeStatus{
		Host: &models.HostStatus{
			PrimaryAddress: &models.PathStatus{},
		},
	}

	pathStatus = GetHostPrimaryAddress(primaryAddressNS)
	c.Assert(pathStatus, Not(IsNil))
}

func (s *ClientTestSuite) TestGetPrimaryAddressIP(c *C) {
	nilHostNS := &models.NodeStatus{
		Host: nil,
	}

	pathStatus := getPrimaryAddressIP(nilHostNS)
	c.Assert(pathStatus, Equals, ipUnavailable)

	nilPrimaryAddressNS := &models.NodeStatus{
		Host: &models.HostStatus{
			PrimaryAddress: nil,
		},
	}

	pathStatus = getPrimaryAddressIP(nilPrimaryAddressNS)
	c.Assert(pathStatus, Equals, ipUnavailable)

	primaryAddressNS := &models.NodeStatus{
		Host: &models.HostStatus{
			PrimaryAddress: &models.PathStatus{},
		},
	}

	pathStatus = getPrimaryAddressIP(primaryAddressNS)
	c.Assert(pathStatus, Equals, "")
}
