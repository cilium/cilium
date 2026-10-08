// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ipam implements the operator-side AWS ENI allocation logic: it
// creates and attaches the ENIs a node needs, maintains the instances view of
// the VPC, and garbage collects the ENIs left behind.
//
// It is registered by the cilium-operator only. The agent's counterpart lives
// in pkg/aws/agent.
package ipam
