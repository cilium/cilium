// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
)

func getEPTemplate(t *testing.T, d *Daemon) *models.EndpointChangeRequest {
	ip4, ip6, err := d.ipam.AllocateNext("", "test", ipam.PoolDefault())
	require.NoError(t, err)
	require.NotNil(t, ip4)
	require.NotNil(t, ip6)

	return &models.EndpointChangeRequest{
		ContainerName: "foo",
		State:         models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		Addressing: &models.AddressPair{
			IPV6: ip6.IP.String(),
			IPV4: ip4.IP.String(),
		},
		Properties: map[string]any{
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
	_, code, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	require.Error(t, err)
	require.Equal(t, apiEndpoint.PutEndpointIDInvalidCode, code)

	// Endpoint was created with invalid data; should transition from
	// WaitingForIdentity -> Invalid.
	assertOnMetric(t, string(models.EndpointStateWaitingDashForDashIdentity), 0)
	assertOnMetric(t, string(models.EndpointStateInvalid), 0)

	// Endpoint is created with initial label as well as disallowed
	// reserved:world label.
	epTemplate.Labels = append(epTemplate.Labels, "reserved:init")
	_, code, err = ds.d.createEndpoint(context.TODO(), epTemplate)
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
	_, code, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	require.Error(t, err)
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

	// Create the endpoint without any labels.
	epTemplate := getEPTemplate(t, ds.d)
	_, _, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	require.NoError(t, err)

	initLbl := labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved)
	expectedLabels := []string{initLbl.String()}
	// Check that the endpoint has the reserved:init label.
	v4ip, err := netip.ParseAddr(epTemplate.Addressing.IPV4)
	require.NoError(t, err)
	ep, err := ds.d.endpointManager.Lookup(endpointid.NewIPPrefixID(v4ip))
	require.NoError(t, err)
	require.Equal(t, expectedLabels, ep.GetOpLabels())

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
	require.Error(t, err)
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
	_, _, err := ds.d.createEndpoint(cancelledContext, epTemplate)
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

type fetcherFn func(run uint, nsName, podName string) (*slim_corev1.Pod, error)

type fetcher struct {
	fn   fetcherFn
	runs uint
}

func (f *fetcher) FetchNamespace(nsName string) (*slim_corev1.Namespace, error) {
	return &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{Name: nsName}}, nil
}

func (f *fetcher) FetchPod(nsName, podName string) (*slim_corev1.Pod, error) {
	defer func() { f.runs++ }()
	return f.fn(f.runs, nsName, podName)
}

func TestHandleOutdatedPodInformer(t *testing.T) {
	defer func(current time.Duration) { handleOutdatedPodInformerRetryPeriod = current }(handleOutdatedPodInformerRetryPeriod)
	handleOutdatedPodInformerRetryPeriod = 1 * time.Millisecond

	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(hivetest.Logger(t), nil, nil, ""))

	notFoundErr := k8sErrors.NewNotFound(schema.GroupResource{Group: "core", Resource: "pod"}, "foo")

	tests := []struct {
		name    string
		epUID   string
		fetcher fetcherFn
		err     func(uid string) error
		retries uint
	}{
		{
			name: "pod not found",
			fetcher: func(_ uint, nsName, podName string) (*slim_corev1.Pod, error) {
				return nil, notFoundErr
			},
			err: func(string) error { return notFoundErr },
		},
		{
			name: "uid mismatch",
			fetcher: func(_ uint, nsName, podName string) (*slim_corev1.Pod, error) {
				return &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{
					Name: podName, Namespace: nsName, UID: "other",
				}}, nil
			},
			err: func(uid string) error {
				if uid == "" {
					return nil
				}
				return podStoreOutdatedErr
			},
			retries: 20,
		},
		{
			name: "uid mismatch, then resolved",
			fetcher: func(run uint, nsName, podName string) (*slim_corev1.Pod, error) {
				uid := types.UID("uid")
				if run < 5 {
					uid = types.UID("other")
				}

				return &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{
					Name: podName, Namespace: nsName, UID: uid,
				}}, nil
			},
			err:     func(string) error { return nil },
			retries: 6,
		},
		{
			name: "pod found",
			fetcher: func(_ uint, nsName, podName string) (*slim_corev1.Pod, error) {
				return &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{
					Name: podName, Namespace: nsName, UID: "uid",
				}}, nil
			},
			err: func(string) error { return nil },
		},
	}

	for _, epUID := range []string{"", "uid"} {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s (epUID: %s)", tt.name, epUID), func(t *testing.T) {
				fetcher := fetcher{fn: tt.fetcher}
				daemon := Daemon{endpointMetadataFetcher: &fetcher}
				ep := endpoint.Endpoint{K8sPodName: "foo", K8sNamespace: "bar", K8sUID: epUID}

				pod, meta, err := daemon.handleOutdatedPodInformer(context.Background(), &ep)
				assert.Equal(t, tt.err(epUID), err)
				if tt.err(epUID) == nil {
					assert.NotNil(t, pod)
					assert.NotNil(t, meta)
				}

				retries := uint(1)
				if tt.retries > 0 && epUID != "" {
					retries = tt.retries
				}
				assert.Equal(t, retries, fetcher.runs, "Incorrect number of retries")
			})
		}
	}
}
