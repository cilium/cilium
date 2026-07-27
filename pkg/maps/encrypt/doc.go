// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package encrypt represents the nodes current encryption state. It is used
// by the datapath to learn current encryption configuration and managed by
// golang linux datapath ./pkg/datapath/linux/ objects. This will reflect any
// key rotations/updates.
// +groupName=maps
package encrypt
