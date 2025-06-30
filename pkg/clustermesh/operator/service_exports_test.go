// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
)

func TestGlobalServiceExportCache(t *testing.T) {
	metrics := NewMetrics()
	globalServiceExports := NewGlobalServiceExportCache(
		metrics.TotalGlobalServiceExports.WithLabelValues("foo"),
	)

	globalServiceExports.OnUpdate(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster1",
		Name:      "reset",
		Namespace: "default",
	})
	// Call OnUpdate twice to check if we don't duplicate this service somehow
	globalServiceExports.OnUpdate(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster1",
		Name:      "reset",
		Namespace: "default",
	})
	require.EqualValues(t, 1, globalServiceExports.Size())
	require.Equal(t, []string{"reset"}, globalServiceExports.GetServiceExportsName("default"))
	require.Len(t, globalServiceExports.GetServiceExportByCluster(types.NamespacedName{
		Namespace: "default",
		Name:      "reset",
	}), 1)
	require.Nil(t, globalServiceExports.GetServiceExportByCluster(types.NamespacedName{
		Namespace: "default",
		Name:      "unknown",
	}))

	require.True(t, globalServiceExports.OnDelete(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster1",
		Name:      "reset",
		Namespace: "default",
	}))
	// Check that calling OnDelete twice doesn't do anything
	require.False(t, globalServiceExports.OnDelete(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster1",
		Name:      "reset",
		Namespace: "default",
	}))
	require.EqualValues(t, 0, globalServiceExports.Size(), "should have no global service exports")
	require.Empty(t, globalServiceExports.cache, "Cache should be fully reset")

	// Initial state
	globalServiceExports.OnUpdate(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster1",
		Name:      "service-1",
		Namespace: "default",
	})
	globalServiceExports.OnUpdate(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster1",
		Name:      "service-2",
		Namespace: "default",
	})
	globalServiceExports.OnUpdate(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster2",
		Name:      "service-2",
		Namespace: "default",
	})
	require.EqualValues(t, 2, globalServiceExports.Size())
	require.Len(t, globalServiceExports.GetServiceExportByCluster(types.NamespacedName{
		Namespace: "default",
		Name:      "service-2",
	}), 2)

	// Delete the service-2 from one cluster
	globalServiceExports.OnDelete(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster2",
		Name:      "service-2",
		Namespace: "default",
	})
	require.EqualValues(t, 2, globalServiceExports.Size())
	require.Len(t, globalServiceExports.GetServiceExportByCluster(types.NamespacedName{
		Namespace: "default",
		Name:      "service-2",
	}), 1)

	// Completely delete service-2
	globalServiceExports.OnDelete(&mcsapitypes.MCSAPIServiceSpec{
		Cluster:   "cluster1",
		Name:      "service-2",
		Namespace: "default",
	})
	require.EqualValues(t, 1, globalServiceExports.Size())
	require.Nil(t, globalServiceExports.GetServiceExportByCluster(types.NamespacedName{
		Namespace: "default",
		Name:      "service-2",
	}))
	require.Nil(t, globalServiceExports.cache["default"]["service-2"])

	// Check that the other service is intact
	require.Len(t, globalServiceExports.GetServiceExportByCluster(types.NamespacedName{
		Namespace: "default",
		Name:      "service-1",
	}), 1)
}
