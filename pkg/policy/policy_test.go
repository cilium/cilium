// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

func TestSearchContextString(t *testing.T) {
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
		require.Equal(t, expected, str)
	}
}

func BenchmarkSearchContextString(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		for _, sc := range []SearchContext{
			{
				Trace: 1,
				Depth: 0,
				From:  labels.ParseLabelArray("a", "t", "b"),
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
				From:  labels.ParseLabelArray("a", "t", "b"),
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
