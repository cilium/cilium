// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package experimental contains a new experimental load-balancer control-plane based
// on StateDB. It aims to simplify the control-plane down to fewer layers and open up
// the ability to modify and observe frontends and backends for variaty of use-cases
// without the need to special-case them.
package experimental
