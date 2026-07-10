// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// XfrmStateInfo represents the key information from an XFRM state
// This struct is used for JSON serialization of XFRM state information
// and is shared between cilium-dbg and cilium-cli for consistency
type XfrmStateInfo struct {
	Encrypt  bool   `json:"encrypt"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	SPI      uint32 `json:"spi"`
	ReqID    uint32 `json:"reqid"`
	AuthAlg  string `json:"auth_alg,omitempty"`
	AuthKey  string `json:"auth_key,omitempty"`
	CryptAlg string `json:"crypt_alg,omitempty"`
	CryptKey string `json:"crypt_key,omitempty"`
	AeadAlg  string `json:"aead_alg,omitempty"`
	AeadKey  string `json:"aead_key,omitempty"`
}
