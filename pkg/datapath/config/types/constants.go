// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// ConstantPrefix is the prefix used to declare configuration constants in the
// datapath's BPF C code. Must match the prefix used by the CONFIG macro in
// static_data.h.
const ConstantPrefix = "__config_"

// ConstantSection is the ELF section used to store configuration variables for
// the Cilium datapath. Must match the section used by the CONFIG macro in
// static_data.h.
const ConstantSection = ".rodata.config"

// ConstantTag is the Go struct tag used to annotate struct fields that should
// be applied as runtime configs when fed into CollectionOptions.Constants.
//
//	DeviceMTU uint16 `config:"device_mtu"`
const ConstantTag = "config"
