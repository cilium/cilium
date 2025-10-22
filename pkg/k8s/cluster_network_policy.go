package k8s

import (
	_ "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	_ "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"
	_ "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
)
