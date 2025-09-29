// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

type ConnectorConfig interface {
	GetPodDeviceHeadroom() uint16
	GetPodDeviceTailroom() uint16
}
