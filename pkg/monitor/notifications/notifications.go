// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package notifications

// RegenNotificationInfo provides information about endpoint regeneration
type RegenNotificationInfo interface {
	GetID() uint64
	GetOpLabels() []string
	GetK8sPodName() string
	GetK8sNamespace() string
	GetID16() uint16
}
