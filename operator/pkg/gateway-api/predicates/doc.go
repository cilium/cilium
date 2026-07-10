// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// predicates holds functions that work as predicates for
// controller-runtime calls, filtering requests send to the watchhandler
// so that only objects that have the predicate function return `true`
// will be sent to the watch handler.
package predicates
