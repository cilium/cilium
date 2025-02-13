// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

// ConstantPrefix is the prefix used to declare configuration constants in the
// datapath's BPF C code. Must match the prefix used by the CONFIG macro in
// static_data.h.
const ConstantPrefix = "__config_"

// Section is the ELF section used to store configuration variables for the
// Cilium datapath. Must match the section used by the CONFIG macro in
// static_data.h.
const Section = ".rodata.config"

// TagName is the name of the struct tag used to annotate configuration fields.
const TagName = "config"
