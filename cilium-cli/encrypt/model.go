// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import "github.com/go-openapi/strfmt"

type clusterStatus struct {
	TotalNodeCount          int              `json:"total-node-count,omitempty"`
	EncDisabledNodeCount    int              `json:"enc-disabled-node-count,omitempty"`
	EncIPsecNodeCount       int              `json:"enc-ipsec-node-count,omitempty"`
	EncWireguardNodeCount   int              `json:"enc-wireguard-node-count,omitempty"`
	IPsecKeysInUseNodeCount map[int64]int64  `json:"ipsec-keys-in-use-node-count,omitempty"`
	IPsecMaxSeqNum          string           `json:"ipsec-max-seq-num,omitempty"`
	IPsecErrCount           int64            `json:"ipsec-err-count,omitempty"`
	XfrmErrors              map[string]int64 `json:"xfrm-errors,omitempty"`
	XfrmErrorNodeCount      map[string]int64 `json:"xfrm-error-node-count,omitempty"`
}

// EncryptionStatus Status of transparent encryption
type EncryptionStatus struct {
	Ipsec     *IPsecStatus     `json:"ipsec,omitempty"`
	Mode      string           `json:"mode,omitempty"`
	Msg       string           `json:"msg,omitempty"`
	Wireguard *WireguardStatus `json:"wireguard,omitempty"`
}

// IPsecStatus Status of the IPsec agent
type IPsecStatus struct {
	DecryptInterfaces []string         `json:"decrypt-interfaces"`
	ErrorCount        int64            `json:"error-count,omitempty"`
	KeysInUse         int64            `json:"keys-in-use,omitempty"`
	MaxSeqNumber      string           `json:"max-seq-number,omitempty"`
	XfrmErrors        map[string]int64 `json:"xfrm-errors,omitempty"`
}

// WireguardStatus Status of the WireGuard agent
type WireguardStatus struct {
	Interfaces     []*WireguardInterface `json:"interfaces"`
	NodeEncryption string                `json:"node-encryption,omitempty"`
}

// WireguardInterface Status of a WireGuard interface
type WireguardInterface struct {
	ListenPort int64            `json:"listen-port,omitempty"`
	Name       string           `json:"name,omitempty"`
	PeerCount  int64            `json:"peer-count,omitempty"`
	Peers      []*WireguardPeer `json:"peers"`
	PublicKey  string           `json:"public-key,omitempty"`
}

// WireguardPeer Status of a WireGuard peer
type WireguardPeer struct {
	AllowedIps        []string        `json:"allowed-ips"`
	Endpoint          string          `json:"endpoint,omitempty"`
	LastHandshakeTime strfmt.DateTime `json:"last-handshake-time,omitempty"`
	PublicKey         string          `json:"public-key,omitempty"`
	TransferRx        int64           `json:"transfer-rx,omitempty"`
	TransferTx        int64           `json:"transfer-tx,omitempty"`
}
