// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"

	pb "github.com/cilium/cilium/api/v1/flow"
)

func mustGetLabelValues(opts *ContextOptions, flow *pb.Flow) []string {
	labels, err := opts.GetLabelValues(flow)
	if err != nil {
		panic(err)
	}
	return labels
}

func TestParseContextOptions(t *testing.T) {
	opts, err := ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "unknown",
				Values: []string{},
			},
		},
	)
	assert.NoError(t, err)
	assert.NotNil(t, opts)

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"invalid"},
			},
		},
	)
	assert.Error(t, err)
	assert.Nil(t, opts)

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"invalid"},
			},
		},
	)
	assert.Error(t, err)
	assert.Nil(t, opts)

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "source=namespace", opts.Status())
	assert.Equal(t, []string{"source"}, opts.GetLabelNames())

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"identity"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "destination=identity,source=namespace", opts.Status())
	assert.Equal(t, []string{"source", "destination"}, opts.GetLabelNames())

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"identity"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"identity"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "destination=identity,source=identity", opts.Status())
	assert.Equal(t, []string{"source", "destination"}, opts.GetLabelNames())

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "source=pod", opts.Status())
	assert.Equal(t, []string{"source"}, opts.GetLabelNames())

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"dns"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "destination=dns", opts.Status())
	assert.Equal(t, []string{"destination"}, opts.GetLabelNames())

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"ip"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "source=ip", opts.Status())
	assert.Equal(t, []string{"source"}, opts.GetLabelNames())

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"pod", "dns"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "source=pod|dns", opts.Status())
	assert.Equal(t, []string{"source"}, opts.GetLabelNames())

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"namespace", "invalid"},
			},
		},
	)
	assert.Error(t, err)
	assert.Nil(t, opts)

	// All of the labelsContext options should work
	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "labelsContext",
				Values: contextLabelsList,
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "labels=source_ip,source_pod,source_namespace,source_workload,source_workload_kind,source_app,destination_ip,destination_pod,destination_namespace,destination_workload,destination_workload_kind,destination_app,traffic_direction", opts.Status())
	assert.Equal(t, contextLabelsList, opts.GetLabelNames())

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "labelsContext",
				Values: []string{"non_existent_label"},
			},
		},
	)
	assert.Error(t, err, "unsupported labelsContext option should error")
	assert.Nil(t, opts)
}

func TestParseGetLabelValues(t *testing.T) {
	opts, err := ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo"}, mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"namespace"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo"}, mustGetLabelValues(opts, &pb.Flow{Destination: &pb.Endpoint{Namespace: "foo"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"identity"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo", "a,b"}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Namespace: "foo"},
		Destination: &pb.Endpoint{Labels: []string{"a", "b"}},
	}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo/foo"}, mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo/bar"}, mustGetLabelValues(opts, &pb.Flow{Destination: &pb.Endpoint{Namespace: "foo", PodName: "bar"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"pod-name"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo-123"}, mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo-123"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"pod-name"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"bar-123"}, mustGetLabelValues(opts, &pb.Flow{Destination: &pb.Endpoint{Namespace: "foo", PodName: "bar-123"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"dns"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo,bar"}, mustGetLabelValues(opts, &pb.Flow{SourceNames: []string{"foo", "bar"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"dns"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"bar"}, mustGetLabelValues(opts, &pb.Flow{DestinationNames: []string{"bar"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"ip"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"1.1.1.1"}, mustGetLabelValues(opts, &pb.Flow{IP: &pb.IP{Source: "1.1.1.1"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"ip"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.2"}, mustGetLabelValues(opts, &pb.Flow{IP: &pb.IP{Destination: "10.0.0.2"}}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"workload-name"},
			},
			{
				Name:   "sourceEgressContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t,
		[]string{"foo/foo-123"},
		mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "worker"}}}, TrafficDirection: pb.TrafficDirection_EGRESS}))
	assert.Equal(t,
		[]string{"worker"},
		mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "worker"}}}, TrafficDirection: pb.TrafficDirection_INGRESS}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"workload-name"},
			},

			{
				Name:   "sourceEgressContext",
				Values: []string{"pod"},
			},
			{
				Name:   "sourceIngressContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t,
		[]string{"worker"},
		mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "worker"}}}, TrafficDirection: pb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"workload-name"},
			},

			{
				Name:   "destinationIngressContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t,
		[]string{"api"},
		mustGetLabelValues(opts, &pb.Flow{Destination: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "api"}}}, TrafficDirection: pb.TrafficDirection_EGRESS}))
	assert.Equal(t,
		[]string{"foo/foo-123"},
		mustGetLabelValues(opts, &pb.Flow{Destination: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "api"}}}, TrafficDirection: pb.TrafficDirection_INGRESS}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"workload-name"},
			},
			{
				Name:   "destinationEgressContext",
				Values: []string{"pod"},
			},
			{
				Name:   "destinationIngressContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t,
		[]string{"api"},
		mustGetLabelValues(opts, &pb.Flow{Destination: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "api"}}}, TrafficDirection: pb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "destinationEgressContext",
				Values: []string{"pod"},
			},
			{
				Name:   "destinationIngressContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t,
		[]string{""},
		mustGetLabelValues(opts, &pb.Flow{Destination: &pb.Endpoint{Namespace: "foo", PodName: "foo-123"}, TrafficDirection: pb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceIngressContext",
				Values: []string{"pod"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t,
		[]string{""},
		mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "worker"}}}, TrafficDirection: pb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN}))
	assert.Equal(t,
		[]string{""},
		mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "api"}}}, TrafficDirection: pb.TrafficDirection_EGRESS}))
	assert.Equal(t,
		[]string{"foo/foo-123"},
		mustGetLabelValues(opts, &pb.Flow{Source: &pb.Endpoint{Namespace: "foo", PodName: "foo-123", Workloads: []*pb.Workload{{Name: "api"}}}, TrafficDirection: pb.TrafficDirection_INGRESS}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace", "dns"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"identity", "pod", "ip"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo", "bar/foo-123"}, mustGetLabelValues(opts, &pb.Flow{
		IP: &pb.IP{
			Destination: "10.0.0.2",
		},
		Source: &pb.Endpoint{
			Namespace: "foo",
		},
		SourceNames: []string{"cilium.io"},
		Destination: &pb.Endpoint{
			Namespace: "bar",
			PodName:   "foo-123",
		},
	}))
	assert.Equal(t, []string{"cilium.io", "a,b"}, mustGetLabelValues(opts, &pb.Flow{
		IP: &pb.IP{
			Destination: "10.0.0.2",
		},
		SourceNames: []string{"cilium.io"},
		Destination: &pb.Endpoint{
			Namespace: "bar",
			PodName:   "foo-123",
			Labels:    []string{"a", "b"},
		},
	}))
	assert.Equal(t, []string{"", "10.0.0.2"}, mustGetLabelValues(opts, &pb.Flow{
		IP: &pb.IP{
			Destination: "10.0.0.2",
		},
	}))

	opts, err = ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "labelsContext",
				Values: contextLabelsList,
			},
		},
	)
	assert.NoError(t, err)
	sourceEndpoint := &pb.Endpoint{
		Namespace: "foo-ns",
		PodName:   "foo-deploy-pod",
		Workloads: []*pb.Workload{{
			Name: "foo-deploy",
			Kind: "Deployment",
		}},
		Labels: []string{
			"k8s:app=fooapp",
		},
	}
	destinationEndpoint := &pb.Endpoint{
		Namespace: "bar-ns",
		PodName:   "bar-deploy-pod",
		Workloads: []*pb.Workload{{
			Name: "bar-deploy",
			Kind: "StatefulSet",
		}},
		Labels: []string{
			"k8s:app=barapp",
		},
	}
	flow := &pb.Flow{
		IP: &pb.IP{
			Source:      "1.2.3.4",
			Destination: "5.6.7.8",
		},
		Source:           sourceEndpoint,
		Destination:      destinationEndpoint,
		TrafficDirection: pb.TrafficDirection_INGRESS,
	}
	assert.Equal(t,
		[]string{
			// source_ip, source_pod, source_namespace, source_workload, source_workload_kind , source_app
			"1.2.3.4", "foo-deploy-pod", "foo-ns", "foo-deploy", "Deployment", "fooapp",
			// destination_ip, destination_pod, destination_namespace, destination_workload, destination_workload_kind, destination_app
			"5.6.7.8", "bar-deploy-pod", "bar-ns", "bar-deploy", "StatefulSet", "barapp",
			// traffic_direction
			"ingress",
		}, mustGetLabelValues(opts, flow),
	)

	// Empty flow should just produce empty values for source/destination labels,
	// and set traffic_direction to "unknown"
	assert.Equal(t,
		[]string{
			"", "", "", "", "", "",
			"", "", "", "", "", "",
			"unknown",
		}, mustGetLabelValues(opts, &pb.Flow{}),
	)
}

func Test_reservedIdentityContext(t *testing.T) {
	opts, err := ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"reserved-identity"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"reserved-identity"},
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"", ""}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Labels: []string{"a", "b"}},
		Destination: &pb.Endpoint{Labels: []string{"c", "d"}},
	}))
	assert.Equal(t, []string{"reserved:kube-apiserver", "reserved:world"}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Labels: []string{"reserved:world", "reserved:kube-apiserver", "cidr:1.2.3.4/32"}},
		Destination: &pb.Endpoint{Labels: []string{"reserved:world", "cidr:1.2.3.4/32"}},
	}))
	assert.Equal(t, []string{"reserved:host", "reserved:remote-node"}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Labels: []string{"a", "b", "reserved:host"}},
		Destination: &pb.Endpoint{Labels: []string{"c", "d", "reserved:remote-node"}},
	}))
}

func Test_workloadContext(t *testing.T) {
	opts, err := ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"workload"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"workload"},
			},
		},
	)
	assert.NoError(t, err)

	assert.Equal(t, []string{"", ""}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Namespace: "foo-ns", PodName: "foo-deploy-pod"},
		Destination: &pb.Endpoint{Namespace: "bar-ns", PodName: "bar-deploy-pod"}}))
	assert.Equal(t, []string{"foo-ns/foo-deploy", "bar-ns/bar-deploy"}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Namespace: "foo-ns", PodName: "foo-deploy-pod", Workloads: []*pb.Workload{{Name: "foo-deploy", Kind: "Deployment"}}},
		Destination: &pb.Endpoint{Namespace: "bar-ns", PodName: "bar-deploy-pod", Workloads: []*pb.Workload{{Name: "bar-deploy", Kind: "Deployment"}}},
	}))
}

func Test_workloadNameContext(t *testing.T) {
	opts, err := ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"workload-name"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"workload-name"},
			},
		},
	)
	assert.NoError(t, err)

	assert.Equal(t, []string{"", ""}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Namespace: "foo-ns", PodName: "foo-deploy-pod"},
		Destination: &pb.Endpoint{Namespace: "bar-ns", PodName: "bar-deploy-pod"}}))
	assert.Equal(t, []string{"foo-deploy", "bar-deploy"}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Namespace: "foo-ns", PodName: "foo-deploy-pod", Workloads: []*pb.Workload{{Name: "foo-deploy", Kind: "Deployment"}}},
		Destination: &pb.Endpoint{Namespace: "bar-ns", PodName: "bar-deploy-pod", Workloads: []*pb.Workload{{Name: "bar-deploy", Kind: "Deployment"}}},
	}))
}

func Test_appContext(t *testing.T) {
	opts, err := ParseContextOptions(
		[]*ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"app"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"app"},
			},
		},
	)
	assert.NoError(t, err)

	assert.Equal(t, []string{"", ""}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Namespace: "foo-ns", PodName: "foo-deploy-pod"},
		Destination: &pb.Endpoint{Namespace: "bar-ns", PodName: "bar-deploy-pod"}}))
	assert.Equal(t, []string{"fooapp", "barapp"}, mustGetLabelValues(opts, &pb.Flow{
		Source:      &pb.Endpoint{Namespace: "foo-ns", PodName: "foo-deploy-pod", Labels: []string{"k8s:app=fooapp"}},
		Destination: &pb.Endpoint{Namespace: "bar-ns", PodName: "bar-deploy-pod", Labels: []string{"k8s:app=barapp"}},
	}))
}

func Test_labelsSetString(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		want   string
	}{
		{
			name:   "nil",
			labels: nil,
			want:   "",
		},
		{
			name:   "empty",
			labels: []string{},
			want:   "",
		},
		{
			// NOTE: "invalid" is not in the contextLabelsList slice and thus
			// should be filtered out.
			name:   "invalid",
			labels: []string{"invalid"},
			want:   "",
		},
		{
			name:   "single",
			labels: []string{"source_pod"},
			want:   "source_pod",
		},
		{
			name:   "duplicated",
			labels: []string{"source_pod", "source_pod"},
			want:   "source_pod",
		},
		{
			name:   "two",
			labels: []string{"source_pod", "source_namespace"},
			want:   "source_pod,source_namespace",
		},
		{
			// NOTE: although implemented with a Go map, (labelsSet).String
			// should consistently output in the order defined by the
			// contextLabelsList slice.
			name:   "three",
			labels: []string{"traffic_direction", "destination_pod", "source_app"},
			want:   "source_app,destination_pod,traffic_direction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newLabelsSet(tt.labels)
			assert.Equal(t, tt.want, s.String())
		})
	}
}
