// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PolicyTestSuite struct{}

var _ = Suite(&PolicyTestSuite{})

func (ds *PolicyTestSuite) TestSearchContextString(c *C) {
	for expected, sc := range map[string]SearchContext{
		"From: [unspec:a, unspec:b, unspec:c] => To: [unspec:d, unspec:e, unspec:f] Ports: [HTTP/TCP, HTTPs/TCP]": {
			Trace: 1,
			Depth: 0,
			From:  labels.ParseLabelArray("a", "c", "b"),
			To:    labels.ParseLabelArray("d", "e", "f"),
			DPorts: []*models.Port{
				{
					Name:     "HTTP",
					Port:     80,
					Protocol: "TCP",
				},
				{
					Name:     "HTTPs",
					Port:     442,
					Protocol: "TCP",
				},
			},
			rulesSelect: false,
		},
		"From: [unspec:a, unspec:b, unspec:c] => To: [unspec:d, unspec:e, unspec:f] Ports: [80/TCP, 442/TCP]": {
			Trace: 1,
			Depth: 0,
			From:  labels.ParseLabelArray("a", "c", "b"),
			To:    labels.ParseLabelArray("d", "e", "f"),
			DPorts: []*models.Port{
				{
					Port:     80,
					Protocol: "TCP",
				},
				{
					Port:     442,
					Protocol: "TCP",
				},
			},
			rulesSelect: false,
		},
		"From: [k8s:a, local:b, unspec:c] => To: [unspec:d, unspec:e, unspec:f]": {
			Trace:       1,
			Depth:       0,
			From:        labels.ParseLabelArray("k8s:a", "unspec:c", "local:b"),
			To:          labels.ParseLabelArray("d", "e", "f"),
			rulesSelect: false,
		},
	} {
		str := sc.String()
		c.Assert(str, Equals, expected)
	}
}

func BenchmarkSearchContextString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sc := range []SearchContext{
			{
				Trace: 1,
				Depth: 0,
				From:  labels.ParseLabelArray("a", "c", "b"),
				To:    labels.ParseLabelArray("d", "e", "f"),
				DPorts: []*models.Port{
					{
						Name:     "HTTP",
						Port:     80,
						Protocol: "TCP",
					},
					{
						Name:     "HTTPs",
						Port:     442,
						Protocol: "TCP",
					},
				},
				rulesSelect: false,
			},
			{
				Trace: 1,
				Depth: 0,
				From:  labels.ParseLabelArray("a", "c", "b"),
				To:    labels.ParseLabelArray("d", "e", "f"),
				DPorts: []*models.Port{
					{
						Port:     80,
						Protocol: "TCP",
					},
					{
						Port:     442,
						Protocol: "TCP",
					},
				},
				rulesSelect: false,
			},
		} {
			_ = sc.String()
		}
	}
}
