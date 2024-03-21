package ciliumconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"
)

func TestGetCiliumConfig(t *testing.T) {
	ctx := context.Background()
	fakeclient, _ := client.NewFakeClientset()

	cmWithData := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"labels": "k8s:key-a k8s:key-b",
		},
	}

	cmNoData := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: "kube-system",
		},
	}

	var ciliumConfigCM *corev1.ConfigMap

	fakeclient.KubernetesFakeClientset.PrependReactor("get", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.GetAction)
		if pa.GetName() == CiliumConfigMapName {
			if ciliumConfigCM == nil {
				return false, nil, errors.New("Not found")
			}
			return true, ciliumConfigCM, nil
		}
		return false, nil, nil
	})

	type testCase struct {
		name                   string
		ciliumConfigCM         *corev1.ConfigMap
		ciliumConfigOverrideCM *corev1.ConfigMap

		expectedData  map[string]string
		expectedError bool
	}

	tcs := []testCase{
		{
			name:           "empty_config",
			ciliumConfigCM: nil,
			expectedData:   nil,
			expectedError:  true,
		},
		{
			name:                   "only_cilium_config",
			ciliumConfigCM:         cmWithData,
			ciliumConfigOverrideCM: nil,
			expectedData: map[string]string{
				"labels": "k8s:key-a k8s:key-b",
			},
		},
		{
			name:                   "no_data_cilium_config",
			ciliumConfigCM:         cmNoData,
			ciliumConfigOverrideCM: nil,
			expectedData:           nil,
		},
	}

	for _, tc := range tcs {
		// Don't run in parallel because tests require to use global variables
		// (config) and variables defined outside the scope of the test run.
		t.Run(tc.name, func(t *testing.T) {
			ciliumConfigCM = tc.ciliumConfigCM
			cm, err := GetCiliumConfig(ctx, fakeclient)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedData, cm.Data)
			}
		})
	}
}
