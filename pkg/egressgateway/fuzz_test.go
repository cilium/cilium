// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"testing"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzGetIfaceFirstIPv4Address(f *testing.F) {
	f.Fuzz(func(t *testing.T, ifaceName string) {
		_, _, _ = getIfaceFirstIPv4Address(ifaceName)
	})
}

func FuzzParseCEGP(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		cegp := &v2.CiliumEgressGatewayPolicy{}
		if cegp.Spec.EgressGateway == nil {
			t.Skip()
		}
		ff.GenerateStruct(cegp)
		_, _ = ParseCEGP(cegp)
	})
}

func FuzzParseCENP(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		cenp := &v2alpha1.CiliumEgressNATPolicy{}
		ff.GenerateStruct(cenp)
		_, _ = ParseCENP(cenp)
	})
}
