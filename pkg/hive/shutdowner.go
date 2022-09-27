// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

type Shutdowner interface {
	Shutdown(error)
}
