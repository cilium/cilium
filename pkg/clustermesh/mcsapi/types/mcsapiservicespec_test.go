// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

func TestMCSAPIServiceSpec(t *testing.T) {
	exportTime := metav1.Now().Rfc3339Copy()
	// We need to do this as unmarshal from json also does this and we do not
	// call the Equal method from the time struct which handle time zone difference
	exportTime.Time = exportTime.Local()

	mcsAPISvcSpec := MCSAPIServiceSpec{
		Cluster:                 "cluster1",
		Name:                    "foo",
		Namespace:               "bar",
		ExportCreationTimestamp: exportTime,
		Ports:                   []mcsapiv1alpha1.ServicePort{},
		Type:                    mcsapiv1alpha1.ClusterSetIP,
		SessionAffinity:         corev1.ServiceAffinityNone,
	}
	require.Equal(t, "cluster1/bar/foo", mcsAPISvcSpec.GetKeyName())

	b, err := mcsAPISvcSpec.Marshal()
	require.NoError(t, err)

	unmarshal := MCSAPIServiceSpec{}
	err = unmarshal.Unmarshal("", b)
	require.NoError(t, err)
	require.EqualValues(t, unmarshal, mcsAPISvcSpec)
}

func TestMCSAPIServiceSpecValidate(t *testing.T) {
	exportTime := metav1.Now().Rfc3339Copy()
	// We need to do this as unmarshal from json also does this and we do not
	// call the Equal method from the time struct which handle time zone difference
	exportTime.Time = exportTime.Local()

	tests := []struct {
		name          string
		mcsAPISvcSpec MCSAPIServiceSpec
		assert        assert.ErrorAssertionFunc
	}{
		{
			name:          "empty",
			mcsAPISvcSpec: MCSAPIServiceSpec{},
			assert:        assert.Error,
		},
		{
			name: "minimum information",
			mcsAPISvcSpec: MCSAPIServiceSpec{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				ExportCreationTimestamp: exportTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			assert: assert.NoError,
		},
		{
			name: "invalid exportCreationTimestamp",
			mcsAPISvcSpec: MCSAPIServiceSpec{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				Type:            mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity: corev1.ServiceAffinityNone,
			},
			assert: assert.Error,
		},
		{
			name: "invalid type",
			mcsAPISvcSpec: MCSAPIServiceSpec{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				ExportCreationTimestamp: exportTime,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			assert: assert.Error,
		},
		{
			name: "invalid session affinity",
			mcsAPISvcSpec: MCSAPIServiceSpec{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				ExportCreationTimestamp: exportTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
			},
			assert: assert.Error,
		},
		{
			name: "invalid name",
			mcsAPISvcSpec: MCSAPIServiceSpec{
				Cluster: "foo", Namespace: "bar",
				ExportCreationTimestamp: exportTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
			},
			assert: assert.Error,
		},
		{
			name: "invalid namespace",
			mcsAPISvcSpec: MCSAPIServiceSpec{
				Cluster: "foo", Name: "qux",
				ExportCreationTimestamp: exportTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			assert: assert.Error,
		},
		{
			name: "invalid cluster",
			mcsAPISvcSpec: MCSAPIServiceSpec{
				Namespace: "bar", Name: "qux",
				ExportCreationTimestamp: exportTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			assert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, tt.mcsAPISvcSpec.validate())
		})
	}
}

func TestValidatingClusterService(t *testing.T) {
	exportTime := metav1.Now().Rfc3339Copy()
	// We need to do this as unmarshal from json also does this and we do not
	// call the Equal method from the time struct which handle time zone difference
	exportTime.Time = exportTime.Local()

	mcsAPISvcSpec := MCSAPIServiceSpec{
		Cluster: "foo", Namespace: "bar", Name: "qux",
		ExportCreationTimestamp: exportTime,
		Type:                    mcsapiv1alpha1.ClusterSetIP,
		SessionAffinity:         corev1.ServiceAffinityNone,
	}
	data, err := mcsAPISvcSpec.Marshal()
	require.NoError(t, err)

	tests := []struct {
		name      string
		key       string
		validator mcsAPIServiceSpecValidator
		errstr    string
	}{
		{
			name:      "valid cluster name",
			validator: ClusterNameValidator("foo"),
		},
		{
			name:      "invalid cluster name",
			validator: ClusterNameValidator("fred"),
			errstr:    "unexpected cluster name: got foo, expected fred",
		},
		{
			name:      "valid namespaced name",
			key:       "bar/qux",
			validator: NamespacedNameValidator(),
		},
		{
			name:      "invalid namespaced name",
			key:       "fred/qux",
			validator: NamespacedNameValidator(),
			errstr:    "namespaced name does not match key: got bar/qux, expected fred/qux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyCreator(tt.validator)()
			err = got.Unmarshal(tt.key, data)
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, mcsAPISvcSpec, got.(*ValidatingMCSAPIServiceSpec).MCSAPIServiceSpec)
		})
	}
}
