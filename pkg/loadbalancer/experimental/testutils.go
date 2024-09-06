// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"testing"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
)

// TestCell provides a cell for testing with the load-balancing Writer and tables.
// The reconciler and the lbmaps
//
// It requires the streams of k8s objects which can be provided with e.g. TestInputsFromFiles().
var TestCell = cell.Module(
	"test",
	"Experimental load-balancing testing",

	cell.Provide(
		func() Config {
			return Config{
				EnableExperimentalLB: true,
				RetryBackoffMin:      0,
				RetryBackoffMax:      0,
			}
		},
		func() ExternalConfig {
			return ExternalConfig{}
		},
	),

	// Provide the tables and [Writer]
	TablesCell,

	// Add in the reflector to allow feeding in the inputs.
	ReflectorCell,
)

// TestInputsFromFiles provides the input streams for the reflector by
// decoding the objects from the given input files.
func TestInputsFromFiles(t *testing.T, inputFiles []string) cell.Cell {
	// Categorize the input files into services and endpoints.
	serviceFiles := []string{}
	endpointSliceFiles := []string{}

	parseEndpoints := func(ev resource.Event[*slim_discoveryv1.EndpointSlice]) resource.Event[*k8s.Endpoints] {
		ev2 := resource.Event[*k8s.Endpoints]{
			Kind: ev.Kind,
			Key:  ev.Key,
			Done: ev.Done,
		}
		if ev.Object != nil {
			ev2.Object = k8s.ParseEndpointSliceV1(ev.Object)

		}
		return ev2
	}

	for _, file := range inputFiles {
		obj, err := testutils.DecodeFile(file)
		if err != nil {
			t.Fatalf("DecodeFile(%s): %s", file, err)
		}
		switch obj := obj.(type) {
		case *slim_corev1.Service:
			serviceFiles = append(serviceFiles, file)
		case *slim_discoveryv1.EndpointSlice:
			endpointSliceFiles = append(endpointSliceFiles, file)
		default:
			t.Fatalf("%s decoded to unhandled type %T", file, obj)
		}
	}

	return cell.Provide(
		resource.EventStreamFromFiles[*slim_corev1.Service](serviceFiles),
		resource.EventStreamFromFiles[*slim_corev1.Pod](nil),
		func() stream.Observable[resource.Event[*k8s.Endpoints]] {
			return stream.Map(
				resource.EventStreamFromFiles[*slim_discoveryv1.EndpointSlice](endpointSliceFiles)(),
				parseEndpoints)
		},
	)
}
