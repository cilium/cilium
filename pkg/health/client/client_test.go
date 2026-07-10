// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
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

	allNodesOptions := []bool{true, false}
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
				for _, allNodesOpt := range allNodesOptions {
					for _, verboseOpt := range verboseOptions {
						for _, localhostOpt := range localhostOptions {
							formatNodeStatus(w, ns, allNodesOpt, verboseOpt, localhostOpt)
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

// used ot update golden files
var update = flag.Bool("update", false, "update golden files")

func createNodes(healthy int, unhealthy int, unknown int) []*models.NodeStatus {

	nodes := make([]*models.NodeStatus, healthy+unhealthy)

	for i := range healthy {
		nodes[i] = &models.NodeStatus{
			Name: fmt.Sprintf("node%d", i),
			Host: &models.HostStatus{
				PrimaryAddress: &models.PathStatus{
					IP: fmt.Sprintf("192.168.1.%d", i),
					HTTP: &models.ConnectivityStatus{
						Status:     "",
						Latency:    10000000,
						LastProbed: "2023-04-01T12:30:00Z",
					},
					Icmp: &models.ConnectivityStatus{
						Status:     "",
						Latency:    10000000,
						LastProbed: "2023-04-01T12:35:00Z",
					},
				},
			},
			HealthEndpoint: &models.EndpointStatus{
				PrimaryAddress: &models.PathStatus{
					IP: fmt.Sprintf("192.168.1.%d", i),
					HTTP: &models.ConnectivityStatus{
						Status:     "",
						Latency:    10000000,
						LastProbed: "2023-04-01T12:40:00Z",
					},
					Icmp: &models.ConnectivityStatus{
						Status:     "",
						Latency:    10000000,
						LastProbed: "2023-04-01T12:45:00Z",
					},
				},
			},
		}
	}

	for i := healthy; i < healthy+unhealthy; i++ {
		nodes[i] = &models.NodeStatus{
			Name: fmt.Sprintf("node%d", i),
			Host: &models.HostStatus{
				PrimaryAddress: &models.PathStatus{
					IP: fmt.Sprintf("192.168.1.%d", i),
					HTTP: &models.ConnectivityStatus{
						Status:     "failed",
						LastProbed: "2023-04-01T12:30:00Z",
					},
					Icmp: &models.ConnectivityStatus{
						Status:     "failed",
						LastProbed: "2023-04-01T12:35:00Z",
					},
				},
			},
			HealthEndpoint: &models.EndpointStatus{
				PrimaryAddress: &models.PathStatus{
					IP: fmt.Sprintf("192.168.1.%d", i),
					HTTP: &models.ConnectivityStatus{
						Status:     "failed",
						LastProbed: "2023-04-01T12:40:00Z",
					},
					Icmp: &models.ConnectivityStatus{
						Status:     "failed",
						LastProbed: "2023-04-01T12:45:00Z",
					},
				},
			},
		}
	}

	for i := healthy + unhealthy; i < healthy+unhealthy+unknown; i++ {
		nodes[i] = &models.NodeStatus{
			Name: fmt.Sprintf("node%d", i),
			Host: &models.HostStatus{
				PrimaryAddress: &models.PathStatus{
					IP: fmt.Sprintf("192.168.1.%d", i),
				},
			},
			HealthEndpoint: &models.EndpointStatus{
				PrimaryAddress: &models.PathStatus{
					IP: fmt.Sprintf("192.168.1.%d", i),
				},
			},
		}
	}
	return nodes
}

func TestFormatHealthStatusResponse(t *testing.T) {

	localNode := &models.SelfStatus{
		Name: "local",
	}

	tests := []struct {
		name       string
		sr         *models.HealthStatusResponse
		allNodes   bool
		verbose    bool
		maxLines   int
		wantLines  int
		wantGolden string
	}{
		{
			name: "all healthy",
			sr: &models.HealthStatusResponse{
				Nodes:         createNodes(4, 0, 0),
				Local:         localNode,
				Timestamp:     "2023-04-01T12:00:00Z",
				ProbeInterval: "1m14s",
			},
			allNodes:   false,
			verbose:    false,
			maxLines:   10,
			wantGolden: "allHealthy",
		},
		{
			name: "all healthy verbose",
			sr: &models.HealthStatusResponse{
				Nodes:         createNodes(4, 0, 0),
				Local:         localNode,
				Timestamp:     "2023-04-01T12:00:00Z",
				ProbeInterval: "1m14s",
			},
			allNodes:   false,
			verbose:    true,
			maxLines:   10,
			wantGolden: "allHealthyVerbose",
		},
		{
			name: "all healthy all nodes",
			sr: &models.HealthStatusResponse{
				Nodes:         createNodes(4, 0, 0),
				Local:         localNode,
				Timestamp:     "2023-04-01T12:00:00Z",
				ProbeInterval: "1m14s",
			},
			allNodes:   true,
			verbose:    false,
			maxLines:   10,
			wantGolden: "allHealthyAllNodes",
		},
		{
			name: "one unhealthy",
			sr: &models.HealthStatusResponse{
				Nodes:         createNodes(3, 1, 0),
				Local:         localNode,
				Timestamp:     "2023-04-01T12:00:00Z",
				ProbeInterval: "8m5s",
			},
			allNodes:   false,
			verbose:    false,
			maxLines:   10,
			wantGolden: "oneUnhealthy",
		},
		{
			name: "one unhealthy verbose",
			sr: &models.HealthStatusResponse{
				Nodes:         createNodes(3, 1, 0),
				Local:         localNode,
				Timestamp:     "2023-04-01T12:00:00Z",
				ProbeInterval: "8m5s",
			},
			allNodes:   false,
			verbose:    true,
			maxLines:   10,
			wantGolden: "oneUnhealthyVerbose",
		},
		{
			name: "one unhealthy all nodes",
			sr: &models.HealthStatusResponse{
				Nodes:         createNodes(3, 1, 0),
				Local:         localNode,
				Timestamp:     "2023-04-01T12:00:00Z",
				ProbeInterval: "8m5s",
			},
			allNodes:   true,
			verbose:    false,
			maxLines:   10,
			wantGolden: "oneUnhealthyAllNodes",
		},
		{
			name: "11 unhealthy",
			sr: &models.HealthStatusResponse{
				Nodes:         createNodes(0, 11, 0),
				Local:         localNode,
				Timestamp:     "2023-04-01T12:00:00Z",
				ProbeInterval: "4m15s",
			},
			allNodes:   false,
			verbose:    false,
			maxLines:   10,
			wantGolden: "elevenUnhealthy",
		},
		{
			name: "11 healthy all nodes",
			sr: &models.HealthStatusResponse{
				Nodes:         createNodes(11, 0, 0),
				Local:         localNode,
				Timestamp:     "2023-04-01T12:00:00Z",
				ProbeInterval: "4m15s",
			},
			allNodes:   true,
			verbose:    false,
			maxLines:   10,
			wantGolden: "elevenHealthyAllNodes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.ReadFile("testdata/" + tt.wantGolden + ".golden")
			if err != nil {
				t.Fatalf("failed to read golden file: %v", err)
			}

			w := &bytes.Buffer{}
			FormatHealthStatusResponse(w, tt.sr, tt.allNodes, tt.verbose, tt.maxLines)

			if *update {
				t.Log("updating golden file")
				f, err := os.Create("testdata/" + tt.wantGolden + ".golden")
				if err != nil {
					t.Fatalf("failed to create golden file: %v", err)
				}
				defer f.Close()
				f.Write([]byte(w.Bytes()))
			}

			require.Equal(t, string(f), w.String())
		})
	}
}
