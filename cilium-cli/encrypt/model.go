// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import "github.com/cilium/cilium/api/v1/models"

type clusterStatus struct {
	TotalNodeCount             int              `json:"total-node-count,omitempty"`
	EncDisabledNodeCount       int              `json:"enc-disabled-node-count,omitempty"`
	EncIPsecNodeCount          int              `json:"enc-ipsec-node-count,omitempty"`
	EncWireguardNodeCount      int              `json:"enc-wireguard-node-count,omitempty"`
	IPsecKeysInUseNodeCount    map[int64]int64  `json:"ipsec-keys-in-use-node-count,omitempty"`
	IPsecMaxSeqNum             string           `json:"ipsec-max-seq-num,omitempty"`
	IPsecErrCount              int64            `json:"ipsec-err-count,omitempty"`
	IPsecPerNodeKey            bool             `json:"ipsec-per-node-key,omitempty"`
	IPsecKeyRotationInProgress bool             `json:"ipsec-key-rotation-in-progress,omitempty"`
	IPsecExpectedKeyCount      int              `json:"ipsec-expected-key-count,omitempty"`
	XfrmErrors                 map[string]int64 `json:"xfrm-errors,omitempty"`
	XfrmErrorNodeCount         map[string]int64 `json:"xfrm-error-node-count,omitempty"`
}

type nodeStatus struct {
	models.EncryptionStatus
	IPsecPerNodeKey            bool `json:"ipsec-per-node-key,omitempty"`
	IPsecKeyRotationInProgress bool `json:"ipsec-key-rotation-in-progress,omitempty"`
	IPsecExpectedKeyCount      int  `json:"ipsec-expected-key-count,omitempty"`
}
