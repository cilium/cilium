// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// TODO(cdc) consider only registering this if in AWS mode.
//
// We currently cannot do this, as not all AWS clusters use ENI mode.

package provider

import (
	"github.com/cilium/cilium/pkg/policy/groups/aws"
)

func init() {
	providers[AWSProvider] = aws.GetIPsFromGroup
}
