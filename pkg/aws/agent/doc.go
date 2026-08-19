// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package agent holds the agent-side AWS integration: the AWS customization of
// the multi-pool IPAM allocator, and the netlink configuration of the devices
// the operator attaches to the node.
//
// It is registered by the cilium-agent only. The operator's counterpart lives in
// pkg/aws/ipam.
package agent
