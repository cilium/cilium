package ciliumconfig

import (
	"context"
	"fmt"
	"time"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-config")

const (
	CiliumConfigMapName         = "cilium-config"
)

func GetCiliumConfig(ctx context.Context, clientset k8sClient.Clientset) (*corev1.ConfigMap, error) {
	cm, found := getConfigMap(ctx, clientset, CiliumConfigMapName)
	if !found {
		return nil, fmt.Errorf("fetch ConfigMap kube-system/%s", CiliumConfigMapName)
	}

	return cm, nil
}

func getConfigMap(ctx context.Context, clientset k8sClient.Clientset, cmName string) (*corev1.ConfigMap, bool) {
	maxRetries := 5
	waitDuration := 1 * time.Second
	attempt := 1

	var cm *corev1.ConfigMap
	var err error
	for attempt <= maxRetries {
		cm, err = clientset.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ctx, cmName, metav1.GetOptions{})
		if err == nil {
			return cm, true
		}

		time.Sleep(waitDuration)
		attempt++
	}

	log.Warnf("Failed to GET %s ConfigMap, error: %v", cmName, err)
	return nil, false
}
