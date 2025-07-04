// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/cilium/cilium/api/v1/models"

type WireguardAgent interface {
	Enabled() bool
	Status(withPeers bool) (*models.WireguardStatus, error)
}
