// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func Test_nodeStatusFromOutput(t *testing.T) {
	testCases := []struct {
		name               string
		inputString        string
		expectedNodeStatus models.EncryptionStatus
	}{
		{
			name:        "Node with no encryption",
			inputString: "Encryption: Disabled",
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "Disabled",
				Ipsec: &models.IPsecStatus{
					DecryptInterfaces: make([]string, 0),
					XfrmErrors:        make(map[string]int64),
				},
				Wireguard: &models.WireguardStatus{
					Interfaces: make([]*models.WireguardInterface, 0),
				},
			},
		},
		{
			name: "Node with no encryption, JSON output",
			inputString: `{
  "mode": "Disabled"
}`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "Disabled",
			},
		},
		{
			name: "Node with IPsec encryption and without max seq. num and errors",
			inputString: `Encryption: IPsec
Decryption interface(s):
Keys in use: 1
Max Seq. Number: N/A
Errors: 0`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "IPsec",
				Ipsec: &models.IPsecStatus{
					MaxSeqNumber:      "N/A",
					KeysInUse:         1,
					DecryptInterfaces: make([]string, 0),
					XfrmErrors:        make(map[string]int64),
				},
				Wireguard: &models.WireguardStatus{
					Interfaces: make([]*models.WireguardInterface, 0),
				},
			},
		},
		{
			name: "Node with IPsec encryption and without max seq. num and errors, JSON output",
			inputString: `{
  "ipsec": {
    "decrypt-interfaces": [],
    "keys-in-use": 1,
    "max-seq-number": "N/A"
  },
  "mode": "IPsec"
}`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "IPsec",
				Ipsec: &models.IPsecStatus{
					MaxSeqNumber:      "N/A",
					KeysInUse:         1,
					DecryptInterfaces: make([]string, 0),
				},
			},
		},
		{
			name: "Node with IPsec encryption, with max seq. num and without errors",
			inputString: `Encryption: IPsec
Decryption interface(s):
Keys in use: 1
Max Seq. Number: 0x66c/0xffffffff
Errors: 0`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "IPsec",
				Ipsec: &models.IPsecStatus{
					MaxSeqNumber:      "0x66c/0xffffffff",
					KeysInUse:         1,
					DecryptInterfaces: make([]string, 0),
					XfrmErrors:        make(map[string]int64),
				},
				Wireguard: &models.WireguardStatus{
					Interfaces: make([]*models.WireguardInterface, 0),
				},
			},
		},
		{
			name: "Node with IPsec encryption, with max seq. num and without errors, JSON output",
			inputString: `{
  "ipsec": {
    "decrypt-interfaces": [],
    "keys-in-use": 1,
    "max-seq-number": "0x66c/0xffffffff"
  },
  "mode": "IPsec"
}`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "IPsec",
				Ipsec: &models.IPsecStatus{
					MaxSeqNumber:      "0x66c/0xffffffff",
					KeysInUse:         1,
					DecryptInterfaces: make([]string, 0),
				},
			},
		},
		{
			name: "Node with IPsec encryption, with max seq. num and IPsec error",
			inputString: `Encryption: IPsec
Decryption interface(s):
Keys in use: 2
Max Seq. Number: 0x66c/0xffffffff
Errors: 2
    XfrmInNoState: 2`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "IPsec",
				Ipsec: &models.IPsecStatus{
					MaxSeqNumber:      "0x66c/0xffffffff",
					KeysInUse:         2,
					ErrorCount:        2,
					DecryptInterfaces: make([]string, 0),
					XfrmErrors: map[string]int64{
						"XfrmInNoState": 2,
					},
				},
				Wireguard: &models.WireguardStatus{
					Interfaces: make([]*models.WireguardInterface, 0),
				},
			},
		},
		{
			name: "Node with IPsec encryption, with max seq. num and IPsec error, JSON output",
			inputString: `{
  "ipsec": {
    "decrypt-interfaces": [],
    "keys-in-use": 2,
    "max-seq-number": "0x66c/0xffffffff",
    "error-count": 2,
    "xfrm-errors": {
      "XfrmInNoState": 2
    }
  },
  "mode": "IPsec"
}`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "IPsec",
				Ipsec: &models.IPsecStatus{
					MaxSeqNumber:      "0x66c/0xffffffff",
					KeysInUse:         2,
					ErrorCount:        2,
					DecryptInterfaces: make([]string, 0),
					XfrmErrors: map[string]int64{
						"XfrmInNoState": 2,
					},
				},
			},
		},
		{
			name: "Node with IPsec encryption, with max seq. num and IPsec errors",
			inputString: `Encryption: IPsec
Decryption interface(s):
Keys in use: 2
Max Seq. Number: 0x66c/0xffffffff
Errors: 3
    XfrmInNoState: 2
    XfrmInHdrError: 1`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "IPsec",
				Ipsec: &models.IPsecStatus{
					MaxSeqNumber:      "0x66c/0xffffffff",
					KeysInUse:         2,
					ErrorCount:        3,
					DecryptInterfaces: make([]string, 0),
					XfrmErrors: map[string]int64{
						"XfrmInNoState":  2,
						"XfrmInHdrError": 1,
					},
				},
				Wireguard: &models.WireguardStatus{
					Interfaces: make([]*models.WireguardInterface, 0),
				},
			},
		},
		{
			name: "Node with IPsec encryption, with max seq. num and IPsec errors, JSON output",
			inputString: `{
  "ipsec": {
    "decrypt-interfaces": [],
    "keys-in-use": 2,
    "max-seq-number": "0x66c/0xffffffff",
    "error-count": 3,
    "xfrm-errors": {
      "XfrmInNoState": 2,
      "XfrmInHdrError": 1
    }
  },
  "mode": "IPsec"
}`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "IPsec",
				Ipsec: &models.IPsecStatus{
					MaxSeqNumber:      "0x66c/0xffffffff",
					KeysInUse:         2,
					ErrorCount:        3,
					DecryptInterfaces: make([]string, 0),
					XfrmErrors: map[string]int64{
						"XfrmInNoState":  2,
						"XfrmInHdrError": 1,
					},
				},
			},
		},
		{
			name:        "Node with Wireguard encryption",
			inputString: "Encryption: Wireguard",
			expectedNodeStatus: models.EncryptionStatus{
				Mode: "Wireguard",
				Ipsec: &models.IPsecStatus{
					DecryptInterfaces: make([]string, 0),
					XfrmErrors:        make(map[string]int64),
				},
				Wireguard: &models.WireguardStatus{
					Interfaces: make([]*models.WireguardInterface, 0),
				},
			},
		},
		{
			name: "Node with Wireguard encryption, JSON output",
			inputString: `{
  "mode": "Wireguard",
  "wireguard": {
  }
}`,
			expectedNodeStatus: models.EncryptionStatus{
				Mode:      "Wireguard",
				Wireguard: &models.WireguardStatus{},
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actualNodeStatus, err := nodeStatusFromOutput(tt.inputString)

		require.NoError(t, err)
		require.Equal(t, tt.expectedNodeStatus, actualNodeStatus)
	}
}

func Test_getClusterStatus(t *testing.T) {
	testCases := []struct {
		name                  string
		nodeStatusMap         map[string]models.EncryptionStatus
		ikProps               ipsecKeyProps
		expectedClusterStatus clusterStatus
	}{
		{
			name: "Nodes with no encryption",
			nodeStatusMap: map[string]models.EncryptionStatus{
				"node1": {
					Mode: "Disabled",
				},
				"node2": {
					Mode: "Disabled",
				},
			},
			expectedClusterStatus: clusterStatus{
				TotalNodeCount:          2,
				EncDisabledNodeCount:    2,
				IPsecKeysInUseNodeCount: make(map[int64]int64),
				XfrmErrors:              make(map[string]int64),
				XfrmErrorNodeCount:      make(map[string]int64),
			},
		},
		{
			name: "Nodes with IPsec encryption without errors",
			nodeStatusMap: map[string]models.EncryptionStatus{
				"node1": {
					Mode: "IPsec",
					Ipsec: &models.IPsecStatus{
						KeysInUse:    1,
						MaxSeqNumber: "0x66c/0xffffffff",
					},
				},
				"node2": {
					Mode: "IPsec",
					Ipsec: &models.IPsecStatus{
						KeysInUse:    1,
						MaxSeqNumber: "0x77c/0xffffffff",
					},
				},
			},
			ikProps: ipsecKeyProps{expectedCount: 1},
			expectedClusterStatus: clusterStatus{
				TotalNodeCount:          2,
				EncIPsecNodeCount:       2,
				IPsecExpectedKeyCount:   1,
				IPsecKeysInUseNodeCount: map[int64]int64{1: 2},
				IPsecMaxSeqNum:          "0x77c/0xffffffff",
				XfrmErrors:              make(map[string]int64),
				XfrmErrorNodeCount:      make(map[string]int64),
			},
		},
		{
			name: "Nodes with IPsec encryption with errors",
			nodeStatusMap: map[string]models.EncryptionStatus{
				"node1": {
					Mode: "IPsec",
					Ipsec: &models.IPsecStatus{
						KeysInUse:    1,
						ErrorCount:   2,
						MaxSeqNumber: "0x66c/0xffffffff",
						XfrmErrors: map[string]int64{
							"XfrmInNoState": 2,
						},
					},
				},
				"node2": {
					Mode: "IPsec",
					Ipsec: &models.IPsecStatus{
						KeysInUse:    2,
						ErrorCount:   3,
						MaxSeqNumber: "0x77c/0xffffffff",
						XfrmErrors: map[string]int64{
							"XfrmInHdrError": 1,
							"XfrmInNoState":  2,
						},
					},
				},
			},
			ikProps: ipsecKeyProps{expectedCount: 1},
			expectedClusterStatus: clusterStatus{
				TotalNodeCount:             2,
				EncIPsecNodeCount:          2,
				IPsecExpectedKeyCount:      1,
				IPsecKeyRotationInProgress: true,
				IPsecKeysInUseNodeCount:    map[int64]int64{1: 1, 2: 1},
				IPsecMaxSeqNum:             "0x77c/0xffffffff",
				IPsecErrCount:              5,
				XfrmErrors: map[string]int64{
					"XfrmInHdrError": 1,
					"XfrmInNoState":  4,
				},
				XfrmErrorNodeCount: map[string]int64{
					"XfrmInHdrError": 1,
					"XfrmInNoState":  2,
				},
			},
		},
		{
			name: "Nodes with Disabled and IPsec encryption with errors",
			nodeStatusMap: map[string]models.EncryptionStatus{
				"node1": {
					Mode: "IPsec",
					Ipsec: &models.IPsecStatus{
						KeysInUse:    1,
						ErrorCount:   2,
						MaxSeqNumber: "0x66c/0xffffffff",
						XfrmErrors: map[string]int64{
							"XfrmInNoState": 2,
						},
					},
				},
				"node2": {
					Mode: "IPsec",
					Ipsec: &models.IPsecStatus{
						KeysInUse:    2,
						ErrorCount:   3,
						MaxSeqNumber: "0x77c/0xffffffff",
						XfrmErrors: map[string]int64{
							"XfrmInHdrError": 1,
							"XfrmInNoState":  2,
						},
					},
				},
				"node3": {
					Mode: "Disabled",
				},
			},
			ikProps: ipsecKeyProps{
				perNode:       true,
				expectedCount: 1,
			},
			expectedClusterStatus: clusterStatus{
				TotalNodeCount:             3,
				EncDisabledNodeCount:       1,
				EncIPsecNodeCount:          2,
				IPsecExpectedKeyCount:      1,
				IPsecPerNodeKey:            true,
				IPsecKeyRotationInProgress: true,
				IPsecKeysInUseNodeCount:    map[int64]int64{1: 1, 2: 1},
				IPsecMaxSeqNum:             "0x77c/0xffffffff",
				IPsecErrCount:              5,
				XfrmErrors: map[string]int64{
					"XfrmInHdrError": 1,
					"XfrmInNoState":  4,
				},
				XfrmErrorNodeCount: map[string]int64{
					"XfrmInHdrError": 1,
					"XfrmInNoState":  2,
				},
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actualClusterStatus, err := getClusterStatus(tt.nodeStatusMap, tt.ikProps)

		require.NoError(t, err)
		require.Equal(t, tt.expectedClusterStatus, actualClusterStatus)
	}
}

func Test_maxSequenceNumber(t *testing.T) {
	testCases := []struct {
		seqNum1           string
		seqNum2           string
		expectedMaxSeqNum string
	}{
		{
			seqNum1:           "N/A",
			seqNum2:           "N/A",
			expectedMaxSeqNum: "N/A",
		},
		{
			seqNum1:           "N/A",
			seqNum2:           "0x77c/0xffffffff",
			expectedMaxSeqNum: "0x77c/0xffffffff",
		},
		{
			seqNum1:           "0x99c/0xffffffff",
			seqNum2:           "0x77c/0xffffffff",
			expectedMaxSeqNum: "0x99c/0xffffffff",
		},
		{
			seqNum1:           "0x99c",
			seqNum2:           "0x77c",
			expectedMaxSeqNum: "0x99c",
		},
	}

	for _, tt := range testCases {
		// function to test
		actualMaxSequenceNumber, err := maxSequenceNumber(tt.seqNum1, tt.seqNum2)

		require.NoError(t, err)
		require.Equal(t, tt.expectedMaxSeqNum, actualMaxSequenceNumber)
	}
}

func Test_expectedIPsecKeyCount(t *testing.T) {
	testCases := []struct {
		ciliumPods int
		fs         features.Set
		perNodeKey bool
		expected   int
	}{
		{
			ciliumPods: 1,
			fs:         features.Set{},
			perNodeKey: false,
			expected:   1,
		},
		{
			ciliumPods: 100,
			fs:         features.Set{},
			perNodeKey: false,
			expected:   1,
		},
		{
			ciliumPods: 10,
			fs:         features.Set{},
			perNodeKey: true,
			expected:   18,
		},
		{
			ciliumPods: 10,
			fs: features.Set{
				features.IPv6: features.Status{Enabled: true},
			},
			perNodeKey: true,
			expected:   36,
		},
		{
			ciliumPods: 10,
			fs: features.Set{
				features.CiliumIPAMMode: features.Status{Mode: "eni"},
			},
			perNodeKey: true,
			expected:   27,
		},
		{
			ciliumPods: 10,
			fs: features.Set{
				features.IPv6:           features.Status{Enabled: true},
				features.CiliumIPAMMode: features.Status{Mode: "azure"},
			},
			perNodeKey: true,
			expected:   54,
		},
		{
			ciliumPods: 20,
			fs: features.Set{
				features.CiliumIPAMMode: features.Status{Mode: "eni"},
			},
			perNodeKey: true,
			expected:   57,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := expectedIPsecKeyCount(tt.ciliumPods, tt.fs, tt.perNodeKey)

		require.Equal(t, tt.expected, actual)
	}
}
