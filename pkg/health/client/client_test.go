// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"io"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ClientTestSuite struct{}

var _ = Suite(&ClientTestSuite{})

func (s *ClientTestSuite) TestConnectivityStatusType(c *C) {
	tests := []struct {
		cst         ConnectivityStatusType
		expectedStr string
	}{
		{
			cst:         ConnStatusReachable,
			expectedStr: "reachable",
		},
		{
			cst:         ConnStatusUnreachable,
			expectedStr: "unreachable",
		},
		{
			cst:         ConnStatusUnknown,
			expectedStr: "unknown",
		},
		{
			cst:         10,
			expectedStr: "unknown",
		},
	}
	for _, tc := range tests {
		c.Assert(tc.cst.String(), Equals, tc.expectedStr)
	}
}

func (s *ClientTestSuite) TestGetConnectivityStatusType(c *C) {
	tests := []struct {
		cs                 *models.ConnectivityStatus
		expectedStatusType ConnectivityStatusType
	}{
		{
			cs:                 &models.ConnectivityStatus{Status: ""},
			expectedStatusType: ConnStatusReachable,
		},
		{
			cs:                 &models.ConnectivityStatus{Status: "failed"},
			expectedStatusType: ConnStatusUnreachable,
		},
		{
			cs:                 nil,
			expectedStatusType: ConnStatusUnknown,
		},
	}
	for _, tc := range tests {
		c.Assert(GetConnectivityStatusType(tc.cs), Equals, tc.expectedStatusType)
	}
}

func (s *ClientTestSuite) TestGetPathConnectivityStatusType(c *C) {
	tests := []struct {
		cp                 *models.PathStatus
		expectedStatusType ConnectivityStatusType
	}{
		{
			cp: &models.PathStatus{
				Icmp: &models.ConnectivityStatus{Status: ""},
				HTTP: &models.ConnectivityStatus{Status: ""},
			},
			expectedStatusType: ConnStatusReachable,
		},
		{
			cp: &models.PathStatus{
				Icmp: &models.ConnectivityStatus{Status: "failed"},
				HTTP: &models.ConnectivityStatus{Status: "failed"},
			},
			expectedStatusType: ConnStatusUnreachable,
		},
		{
			cp: &models.PathStatus{
				Icmp: &models.ConnectivityStatus{Status: ""},
				HTTP: &models.ConnectivityStatus{Status: "failed"},
			},
			expectedStatusType: ConnStatusUnreachable,
		},
		{
			cp: &models.PathStatus{
				Icmp: &models.ConnectivityStatus{Status: "failed"},
				HTTP: &models.ConnectivityStatus{Status: ""},
			},
			expectedStatusType: ConnStatusUnreachable,
		},
		{
			cp: &models.PathStatus{
				Icmp: &models.ConnectivityStatus{Status: "failed"},
				HTTP: nil,
			},
			expectedStatusType: ConnStatusUnreachable,
		},
		{
			cp: &models.PathStatus{
				Icmp: nil,
				HTTP: &models.ConnectivityStatus{Status: "failed"},
			},
			expectedStatusType: ConnStatusUnreachable,
		},
		{
			cp: &models.PathStatus{
				Icmp: nil,
				HTTP: nil,
			},
			expectedStatusType: ConnStatusUnknown,
		},
		{
			cp: &models.PathStatus{
				Icmp: &models.ConnectivityStatus{Status: ""},
				HTTP: nil,
			},
			expectedStatusType: ConnStatusUnknown,
		},
		{
			cp: &models.PathStatus{
				Icmp: nil,
				HTTP: &models.ConnectivityStatus{Status: ""},
			},
			expectedStatusType: ConnStatusUnknown,
		},
	}
	for _, tc := range tests {
		c.Assert(GetPathConnectivityStatusType(tc.cp), Equals, tc.expectedStatusType)
	}
}

func (s *ClientTestSuite) TestFormatNodeStatus(c *C) {
	// This test generates permutations of models.NodeStatus and sees whether
	// the calls to formatNodeStatus panic; the result of this test being
	// successful is whether the test does not panic.

	// not testing output, just that permutations of NodeStatus don't cause
	// panics.
	w := io.Discard

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

	// Assemble possible health-endpoint statuses.
	possibleEndpointStatuses := []*models.EndpointStatus{
		nil,
	}
	for _, possiblePrimaryAddress := range possiblePathStatuses {
		hostStatus := &models.EndpointStatus{
			PrimaryAddress:     possiblePrimaryAddress,
			SecondaryAddresses: possibleSecondaryAddresses,
		}
		possibleEndpointStatuses = append(possibleEndpointStatuses, hostStatus)
	}

	printAllOptions := []bool{true, false}
	succinctOptions := []bool{true, false}
	verboseOptions := []bool{true, false}
	localhostOptions := []bool{true, false}

	for _, possibleEndpointStatus := range possibleEndpointStatuses {
		for _, hostStatus := range possibleHostStatuses {
			for _, name := range possibleNames {
				ns := &models.NodeStatus{
					HealthEndpoint: possibleEndpointStatus,
					Host:           hostStatus,
					Name:           name,
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

func (s *ClientTestSuite) TestGetAllEndpointAddresses(c *C) {
	var (
		primary    = models.PathStatus{IP: "1.1.1.1"}
		secondary1 = models.PathStatus{IP: "2.2.2.2"}
		secondary2 = models.PathStatus{IP: "3.3.3.3"}
	)

	tests := []struct {
		node     *models.NodeStatus
		expected []*models.PathStatus
	}{
		{
			node:     &models.NodeStatus{},
			expected: nil,
		},
		{
			node: &models.NodeStatus{
				HealthEndpoint: &models.EndpointStatus{
					PrimaryAddress: &primary,
				}},
			expected: []*models.PathStatus{&primary},
		},
		{
			node: &models.NodeStatus{
				HealthEndpoint: &models.EndpointStatus{
					PrimaryAddress:     &primary,
					SecondaryAddresses: []*models.PathStatus{&secondary1, &secondary2},
				}},
			expected: []*models.PathStatus{&primary, &secondary1, &secondary2},
		},
	}
	for _, tc := range tests {
		c.Assert(GetAllEndpointAddresses(tc.node), checker.DeepEquals, tc.expected)
	}
}
