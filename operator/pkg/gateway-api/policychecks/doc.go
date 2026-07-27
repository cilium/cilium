// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// policychecks holds objects that are used to be able run checks of various
// types of Policy for common problems, particularly related to things like:
//
// * TargetRef verification
// * Checking that references exist
//
// In each of these cases, it's expected that each check will do its job,
// then update the Conditions of the source object using SetAncestorCondition.
package policychecks
