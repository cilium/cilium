// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// routechecks holds a number of objects that fulfill the Input interface;
// this interface is used to be able to generically run checks of various
// types of Routes for common problems, particularly related to things like:
//
// * Route -> Gateway attachment
// * Checking that references exist
// * ReferenceGrant checks
//
// In each of these cases, it's expected that each check will do its job,
// then update the Conditions of the Input object using SetParentCondition.
//
// The checks themselves are in `gateway_checks.go` and `route_checks.go`, while
// the Input interface implementations are in the other files.
package routechecks
