// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

type CaptureRule struct {
	RuleId   uint16 `align:"rule_id"`
	Reserved uint16 `align:"reserved"`
	CapLen   uint32 `align:"cap_len"`
}
