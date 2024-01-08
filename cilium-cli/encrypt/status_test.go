// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_nodeStatusFromString(t *testing.T) {
	testCases := []struct {
		name               string
		nodeName           string
		inputString        string
		expectedNodeStatus nodeStatus
	}{
		{
			name:        "Node with no encryption",
			nodeName:    "node1",
			inputString: "Encryption: Disabled",
			expectedNodeStatus: nodeStatus{
				NodeName:       "node1",
				EncryptionType: "Disabled",
				XfrmErrors:     make(map[string]int),
			},
		},
		{
			name:     "Node with IPsec encryption and without max seq. num and errors",
			nodeName: "node2",
			inputString: `Encryption: IPsec
Decryption interface(s):
Keys in use: 1
Max Seq. Number: N/A
Errors: 0`,
			expectedNodeStatus: nodeStatus{
				NodeName:       "node2",
				EncryptionType: "IPsec",
				IPsecMaxSeqNum: "N/A",
				IPsecKeysInUse: 1,
				XfrmErrors:     make(map[string]int),
			},
		},
		{
			name:     "Node with IPsec encryption, with max seq. num and without errors",
			nodeName: "node3",
			inputString: `Encryption: IPsec
Decryption interface(s):
Keys in use: 1
Max Seq. Number: 0x66c/0xffffffff
Errors: 0`,
			expectedNodeStatus: nodeStatus{
				NodeName:       "node3",
				EncryptionType: "IPsec",
				IPsecMaxSeqNum: "0x66c/0xffffffff",
				IPsecKeysInUse: 1,
				XfrmErrors:     make(map[string]int),
			},
		},
		{
			name:     "Node with IPsec encryption, with max seq. num and IPsec error",
			nodeName: "node4",
			inputString: `Encryption: IPsec
Decryption interface(s):
Keys in use: 2
Max Seq. Number: 0x66c/0xffffffff
Errors: 2
    XfrmInNoState: 2`,
			expectedNodeStatus: nodeStatus{
				NodeName:       "node4",
				EncryptionType: "IPsec",
				IPsecMaxSeqNum: "0x66c/0xffffffff",
				IPsecKeysInUse: 2,
				IPsecErrCount:  2,
				XfrmErrors: map[string]int{
					"XfrmInNoState": 2,
				},
			},
		},
		{
			name:     "Node with IPsec encryption, with max seq. num and IPsec errors",
			nodeName: "node5",
			inputString: `Encryption: IPsec
Decryption interface(s):
Keys in use: 2
Max Seq. Number: 0x66c/0xffffffff
Errors: 3
    XfrmInNoState: 2
    XfrmInHdrError: 1`,
			expectedNodeStatus: nodeStatus{
				NodeName:       "node5",
				EncryptionType: "IPsec",
				IPsecMaxSeqNum: "0x66c/0xffffffff",
				IPsecKeysInUse: 2,
				IPsecErrCount:  3,
				XfrmErrors: map[string]int{
					"XfrmInNoState":  2,
					"XfrmInHdrError": 1,
				},
			},
		},
		{
			name:        "Node with Wireguard encryption",
			nodeName:    "node6",
			inputString: "Encryption: Wireguard",
			expectedNodeStatus: nodeStatus{
				NodeName:       "node6",
				EncryptionType: "Wireguard",
				XfrmErrors:     make(map[string]int),
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actualNodeStatus, err := nodeStatusFromString(tt.nodeName, tt.inputString)

		require.NoError(t, err)
		require.Equal(t, tt.expectedNodeStatus, actualNodeStatus)
	}
}

func Test_clusterNodeStatus(t *testing.T) {
	testCases := []struct {
		name                  string
		nodeStatusMap         map[string]nodeStatus
		expectedClusterStatus clusterStatus
	}{
		{
			name: "Nodes with no encryption",
			nodeStatusMap: map[string]nodeStatus{
				"node1": {
					NodeName:       "node1",
					EncryptionType: "Disabled",
					XfrmErrors:     make(map[string]int),
				},
				"node2": {
					NodeName:       "node2",
					EncryptionType: "Disabled",
					XfrmErrors:     make(map[string]int),
				},
			},
			expectedClusterStatus: clusterStatus{
				TotalNodeCount:          2,
				EncDisabledNodeCount:    2,
				IPsecKeysInUseNodeCount: make(map[int]int),
				XfrmErrors:              make(map[string]int),
				XfrmErrorNodeCount:      make(map[string]int),
			},
		},
		{
			name: "Nodes with IPsec encryption without errors",
			nodeStatusMap: map[string]nodeStatus{
				"node1": {
					NodeName:       "node1",
					EncryptionType: "IPsec",
					IPsecMaxSeqNum: "0x66c/0xffffffff",
					IPsecKeysInUse: 1,
					XfrmErrors:     make(map[string]int),
				},
				"node2": {
					NodeName:       "node2",
					EncryptionType: "IPsec",
					IPsecMaxSeqNum: "0x77c/0xffffffff",
					IPsecKeysInUse: 1,
					XfrmErrors:     make(map[string]int),
				},
			},
			expectedClusterStatus: clusterStatus{
				TotalNodeCount:          2,
				EncIPsecNodeCount:       2,
				IPsecKeysInUseNodeCount: map[int]int{1: 2},
				IPsecMaxSeqNum:          "0x77c/0xffffffff",
				XfrmErrors:              make(map[string]int),
				XfrmErrorNodeCount:      make(map[string]int),
			},
		},
		{
			name: "Nodes with IPsec encryption with errors",
			nodeStatusMap: map[string]nodeStatus{
				"node1": {
					NodeName:       "node1",
					EncryptionType: "IPsec",
					IPsecMaxSeqNum: "0x66c/0xffffffff",
					IPsecKeysInUse: 1,
					IPsecErrCount:  2,
					XfrmErrors: map[string]int{
						"XfrmInNoState": 2,
					},
				},
				"node2": {
					NodeName:       "node2",
					EncryptionType: "IPsec",
					IPsecMaxSeqNum: "0x77c/0xffffffff",
					IPsecKeysInUse: 2,
					IPsecErrCount:  3,
					XfrmErrors: map[string]int{
						"XfrmInHdrError": 1,
						"XfrmInNoState":  2,
					},
				},
			},
			expectedClusterStatus: clusterStatus{
				TotalNodeCount:          2,
				EncIPsecNodeCount:       2,
				IPsecKeysInUseNodeCount: map[int]int{1: 1, 2: 1},
				IPsecMaxSeqNum:          "0x77c/0xffffffff",
				IPsecErrCount:           5,
				XfrmErrors: map[string]int{
					"XfrmInHdrError": 1,
					"XfrmInNoState":  4,
				},
				XfrmErrorNodeCount: map[string]int{
					"XfrmInHdrError": 1,
					"XfrmInNoState":  2,
				},
			},
		},
		{
			name: "Nodes with Disabled and IPsec encryption with errors",
			nodeStatusMap: map[string]nodeStatus{
				"node1": {
					NodeName:       "node1",
					EncryptionType: "IPsec",
					IPsecMaxSeqNum: "0x66c/0xffffffff",
					IPsecKeysInUse: 1,
					IPsecErrCount:  2,
					XfrmErrors: map[string]int{
						"XfrmInNoState": 2,
					},
				},
				"node2": {
					NodeName:       "node2",
					EncryptionType: "IPsec",
					IPsecMaxSeqNum: "0x77c/0xffffffff",
					IPsecKeysInUse: 2,
					IPsecErrCount:  3,
					XfrmErrors: map[string]int{
						"XfrmInHdrError": 1,
						"XfrmInNoState":  2,
					},
				},
				"node3": {
					NodeName:       "node3",
					EncryptionType: "Disabled",
					XfrmErrors:     make(map[string]int),
				},
			},
			expectedClusterStatus: clusterStatus{
				TotalNodeCount:          3,
				EncDisabledNodeCount:    1,
				EncIPsecNodeCount:       2,
				IPsecKeysInUseNodeCount: map[int]int{1: 1, 2: 1},
				IPsecMaxSeqNum:          "0x77c/0xffffffff",
				IPsecErrCount:           5,
				XfrmErrors: map[string]int{
					"XfrmInHdrError": 1,
					"XfrmInNoState":  4,
				},
				XfrmErrorNodeCount: map[string]int{
					"XfrmInHdrError": 1,
					"XfrmInNoState":  2,
				},
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actualClusterStatus, err := clusterNodeStatus(tt.nodeStatusMap)

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
