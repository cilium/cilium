// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	// This package is having all supported envoy protobuf objects for envoy unmarshalling.
	// Such indirect import helps to reduce the effort of adding new envoy protobuf objects,
	// as we are already upgrading cilium/cilium version regularly.
	_ "github.com/cilium/cilium/pkg/envoy/resource"
)
