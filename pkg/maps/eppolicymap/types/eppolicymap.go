// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/bpf/types"

type EndpointKey struct{ types.EndpointKey }

type EPPolicyValue struct{ Fd uint32 }
