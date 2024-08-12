// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
)

func getEPTemplate(t *testing.T, d *Daemon) *models.EndpointChangeRequest {
	ip4, ip6, err := d.ipam.AllocateNext("", "test", ipam.PoolDefault())
	require.Equal(t, nil, err)
	require.NotNil(t, ip4)
	require.NotNil(t, ip6)

	return &models.EndpointChangeRequest{
		ContainerName: "foo",
		State:         models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		Addressing: &models.AddressPair{
			IPV6: ip6.IP.String(),
			IPV4: ip4.IP.String(),
		},
		Properties: map[string]interface{}{
			endpoint.PropertySkipBPFRegeneration: true,
			endpoint.PropertyFakeEndpoint:        true,
		},
	}
}

func TestEndpointAddReservedLabelEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testEndpointAddReservedLabel(t)
}

func (ds *DaemonSuite) testEndpointAddReservedLabel(t *testing.T) {
	assertOnMetric(t, string(models.EndpointStateWaitingDashForDashIdentity), 0)

	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.Labels = []string{"reserved:world"}
	_, code, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.NotNil(t, err)
	require.Equal(t, apiEndpoint.PutEndpointIDInvalidCode, code)

	// Endpoint was created with invalid data; should transition from
	// WaitingForIdentity -> Invalid.
	assertOnMetric(t, string(models.EndpointStateWaitingDashForDashIdentity), 0)
	assertOnMetric(t, string(models.EndpointStateInvalid), 0)

	// Endpoint is created with initial label as well as disallowed
	// reserved:world label.
	epTemplate.Labels = append(epTemplate.Labels, "reserved:init")
	_, code, err = ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.Condition(t, errorMatch(err, "not allowed to add reserved labels:.+"))
	require.Equal(t, apiEndpoint.PutEndpointIDInvalidCode, code)

	// Endpoint was created with invalid data; should transition from
	// WaitingForIdentity -> Invalid.
	assertOnMetric(t, string(models.EndpointStateWaitingDashForDashIdentity), 0)
	assertOnMetric(t, string(models.EndpointStateInvalid), 0)
}

func TestEndpointAddInvalidLabelEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testEndpointAddInvalidLabel(t)
}

func (ds *DaemonSuite) testEndpointAddInvalidLabel(t *testing.T) {
	assertOnMetric(t, string(models.EndpointStateWaitingDashForDashIdentity), 0)

	epTemplate := getEPTemplate(t, ds.d)
	epTemplate.Labels = []string{"reserved:foo"}
	_, code, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.NotNil(t, err)
	require.Equal(t, apiEndpoint.PutEndpointIDInvalidCode, code)

	// Endpoint was created with invalid data; should transition from
	// WaitingForIdentity -> Invalid.
	assertOnMetric(t, string(models.EndpointStateWaitingDashForDashIdentity), 0)
	assertOnMetric(t, string(models.EndpointStateInvalid), 0)
}

func TestEndpointAddNoLabelsEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testEndpointAddNoLabels(t)
}

func (ds *DaemonSuite) testEndpointAddNoLabels(t *testing.T) {
	assertOnMetric(t, string(models.EndpointStateWaitingDashForDashIdentity), 0)

	// For this test case, we want to allow the endpoint controllers to rebuild
	// the endpoint after getting new labels.
	ds.OnQueueEndpointBuild = ds.d.QueueEndpointBuild

	// Create the endpoint without any labels.
	epTemplate := getEPTemplate(t, ds.d)
	_, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	require.Nil(t, err)

	expectedLabels := labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	// Check that the endpoint has the reserved:init label.
	v4ip, err := netip.ParseAddr(epTemplate.Addressing.IPV4)
	require.Nil(t, err)
	ep, err := ds.d.endpointManager.Lookup(endpointid.NewIPPrefixID(v4ip))
	require.Nil(t, err)
	require.EqualValues(t, expectedLabels, ep.OpLabels.IdentityLabels())

	secID := ep.WaitForIdentity(3 * time.Second)
	require.NotNil(t, secID)
	require.Equal(t, identity.ReservedIdentityInit, secID.ID)

	// Endpoint should transition from Regenerating -> Ready after we've
	// waitied for its new identity. The presence of new labels triggers a
	// regeneration.
	assertOnMetric(t, string(models.EndpointStateRegenerating), 0)
	assertOnMetric(t, string(models.EndpointStateReady), 1)
}

func (ds *DaemonSuite) testUpdateSecLabels(t *testing.T) {
	lbls := labels.NewLabelsFromModel([]string{"reserved:world"})
	code, err := ds.d.modifyEndpointIdentityLabelsFromAPI("1", lbls, nil)
	require.NotNil(t, err)
	require.Equal(t, apiEndpoint.PatchEndpointIDLabelsUpdateFailedCode, code)
}

func TestUpdateSecLabelsEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testUpdateSecLabels(t)
}

func (ds *DaemonSuite) testUpdateLabelsFailed(t *testing.T) {
	cancelledContext, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
	cancelFunc() // Cancel immediately to trigger the codepath to test.

	// Create the endpoint without any labels.
	epTemplate := getEPTemplate(t, ds.d)
	_, _, err := ds.d.createEndpoint(cancelledContext, ds, epTemplate)
	require.ErrorContains(t, err, "request cancelled while resolving identity")

	assertOnMetric(t, string(models.EndpointStateReady), 0)
}

func TestUpdateLabelsFailedEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testUpdateLabelsFailed(t)
}

func getMetricValue(state string) int64 {
	return int64(metrics.GetGaugeValue(metrics.EndpointStateCount.WithLabelValues(state)))
}

func assertOnMetric(t *testing.T, state string, expected int64) {
	_, _, line, _ := runtime.Caller(1)

	obtainedValues := make(map[int64]struct{}, 0)
	err := testutils.WaitUntil(func() bool {
		obtained := getMetricValue(state)
		obtainedValues[obtained] = struct{}{}
		return obtained == expected
	}, 10*time.Second)
	if err != nil {
		// We are printing the map here to show every unique obtained metrics
		// value because these values change rapidly and it may be misleading
		// to only show the last obtained value.
		t.Errorf("Metrics assertion failed on line %d for Endpoint state %s: obtained %v, expected %d",
			line, state, obtainedValues, expected)
	}
}
