// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Note: this should be included in operator-aws and operator-generic builds.
//
// We cannot restrict this to operator-aws builds, however, because the AWS build
// is only used if ENI IPAM is enabled, and there are AWS clusters that
// don't use ENI IPAM.

//go:build ipam_provider_aws || ipam_provider_operator

package provider

import (
	"github.com/cilium/cilium/pkg/policy/groups/aws"
)

func init() {
	providers[AWSProvider] = aws.GetIPsFromGroup
}
