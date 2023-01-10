// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

// SecurityGroup is the representation of an AWS Security Group
//
// +k8s:deepcopy-gen=true
type SecurityGroup struct {
	// ID is the SecurityGroup ID
	ID string

	// VpcID is the VPC ID in which the security group resides
	VpcID string

	// Tags are the tags of the security group
	Tags ipamTypes.Tags
}

// SecurityGroupMap indexes AWS Security Groups by security group ID
type SecurityGroupMap map[string]*SecurityGroup
