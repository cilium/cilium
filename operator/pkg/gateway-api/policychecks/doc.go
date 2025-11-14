// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// policychecks holds a number of objects that fulfill the Input interface;
// this interface is used to be able to generically run checks of various
// types of Policy for common problems, particularly related to things like:
//
// * TargetRef verification
// * Checking that references exist
//
// In each of these cases, it's expected that each check will do its job,
// then update the Conditions of the Input object using SetAncestorCondition.
//
// The checks themselves are in `policy_checks.go`, while
// the Input interface implementation is in the other files.
package policychecks
