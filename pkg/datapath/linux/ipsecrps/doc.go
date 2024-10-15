// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ipsecrps plumbs the necessary configuration into the Linux
// datapath to enable accelerated IPSec via Receive Package Steering
// (RPS). If IPSec RPS is enabled, then a couple of defines are added
// into the datapath, otherwise no action is taken. The configuration
// validates that the required XDP mode and encryption mode are in place
// when a user requests for the feature to be enabled. If the required XDP
// mode or encryption mode is not configured, and the feature is enabled,
// an error is returned.
//
// To implement the configuration, a two stage process is used. First, the
// hive gathers the user provided configuration via runtime flags. If the
// feature is to be enabled based on these flags, an XDP Enabler and CPU Enabler
// are injected into the hive to request and validate that XDP is enabled in
// Native mode and that the CPU Map is available. Second, the hive gathers the
// configuration provided via the runtime flags, the materialized daemon
// configuration, the materialized XDP configuration, and the materialized CPU
// Map configuration. These objects are then used to perform validation.
// If validation passes, a final configuration object is injected into the
// hive which contains the datapath define macros (if necessary) and a boolean
// indicating if the feature is enabled.
package ipsecrps
