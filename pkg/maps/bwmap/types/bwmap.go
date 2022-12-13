// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

type EdtId struct {
	Id uint64 `align:"id"`
}

type EdtInfo struct {
	Bps             uint64    `align:"bps"`
	TimeLast        uint64    `align:"t_last"`
	TimeHorizonDrop uint64    `align:"t_horizon_drop"`
	Pad             [4]uint64 `align:"pad"`
}
