// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

func CreateMaps() {
	CreatePolicyMaps()
	CreateSIDMap()
	CreateVRFMaps()
}
