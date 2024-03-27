package ciliumidentity

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"
)

func TestGetIDRelevantLabelsFromConfigMap(t *testing.T) {
	ctx := context.Background()
	fakeclient, _ := client.NewFakeClientset()

	ciliumConfigCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ciliumConfigMapName,
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"labels": "k8s:key-a k8s:key-b",
		},
	}
	fakeclient.KubernetesFakeClientset.PrependReactor("get", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.GetAction)
		if pa.GetName() != ciliumConfigMapName {
			return false, nil, nil
		}
		return true, ciliumConfigCM, nil
	})

	expectedFilter := []string{"k8s:key-a", "k8s:key-b"}
	filter, err := GetIDRelevantLabelsFromConfigMap(ctx, fakeclient)
	assert.NoError(t, err)
	assert.Equal(t, expectedFilter, filter)
}
