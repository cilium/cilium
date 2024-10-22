// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/health/models"
)

func TestConnectivityStatusType(t *testing.T) {
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
		t.Run(tc.expectedStr, func(t *testing.T) {
			require.Equal(t, tc.expectedStr, tc.cst.String())
		})
	}
}

func TestGetConnectivityStatusType(t *testing.T) {
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
		t.Run(tc.expectedStatusType.String(), func(t *testing.T) {
			require.Equal(t, tc.expectedStatusType, GetConnectivityStatusType(tc.cs))
		})
	}
}

func TestGetPathConnectivityStatusType(t *testing.T) {
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
		t.Run(tc.expectedStatusType.String(), func(t *testing.T) {
			require.Equal(t, tc.expectedStatusType, GetPathConnectivityStatusType(tc.cp))
		})
	}
}

func TestFormatNodeStatus(t *testing.T) {
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

func TestGetHostPrimaryAddress(t *testing.T) {
	nilHostNS := &models.NodeStatus{
		Host: nil,
	}

	pathStatus := GetHostPrimaryAddress(nilHostNS)
	require.Nil(t, pathStatus)

	nilPrimaryAddressNS := &models.NodeStatus{
		Host: &models.HostStatus{
			PrimaryAddress: nil,
		},
	}

	pathStatus = GetHostPrimaryAddress(nilPrimaryAddressNS)
	require.Nil(t, pathStatus)

	primaryAddressNS := &models.NodeStatus{
		Host: &models.HostStatus{
			PrimaryAddress: &models.PathStatus{},
		},
	}

	pathStatus = GetHostPrimaryAddress(primaryAddressNS)
	require.NotNil(t, pathStatus)
}

func TestGetPrimaryAddressIP(t *testing.T) {
	nilHostNS := &models.NodeStatus{
		Host: nil,
	}

	pathStatus := getPrimaryAddressIP(nilHostNS)
	require.Equal(t, ipUnavailable, pathStatus)

	nilPrimaryAddressNS := &models.NodeStatus{
		Host: &models.HostStatus{
			PrimaryAddress: nil,
		},
	}

	pathStatus = getPrimaryAddressIP(nilPrimaryAddressNS)
	require.Equal(t, ipUnavailable, pathStatus)

	primaryAddressNS := &models.NodeStatus{
		Host: &models.HostStatus{
			PrimaryAddress: &models.PathStatus{},
		},
	}

	pathStatus = getPrimaryAddressIP(primaryAddressNS)
	require.Empty(t, pathStatus)
}

func TestGetAllEndpointAddresses(t *testing.T) {
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
		require.Equal(t, tc.expected, GetAllEndpointAddresses(tc.node))
	}
}
