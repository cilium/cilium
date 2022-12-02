// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy/api"
)

func FuzzRegenerateGatewayConfigs(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		nodes := make([]nodeTypes.Node, 0)
		ff.CreateSlice(&nodes)
		if len(nodes) == 0 {
			t.Skip()
		}
		policyConfigs := make(map[policyID]*PolicyConfig)
		ff.FuzzMap(&policyConfigs)
		if len(policyConfigs) == 0 {
			t.Skip()
		}
		for _, pc := range policyConfigs {
			if pc.policyGwConfig == nil {
				pc.policyGwConfig = &policyGatewayConfig{}
				iface, err := ff.GetString()
				if err != nil {
					t.Skip()
				}
				pc.policyGwConfig.iface = iface
			}
			selector := &slimv1.LabelSelector{}
			ff.GenerateStruct(selector)
			if len(selector.MatchLabels) == 0 {
				t.Skip()
			}
			pc.policyGwConfig.nodeSelector = api.NewESFromK8sLabelSelector("", selector)
		}
		manager := &Manager{nodes: nodes, policyConfigs: policyConfigs}
		manager.regenerateGatewayConfigs()
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
