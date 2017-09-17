/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package objectmeta

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/api/testapi"
	"k8s.io/kubernetes/test/integration/framework"
)

func TestIgnoreClusterName(t *testing.T) {
	config := framework.NewMasterConfig()
	_, s, closeFn := framework.RunAMaster(config)
	defer closeFn()

	client := clientset.NewForConfigOrDie(&restclient.Config{Host: s.URL, ContentConfig: restclient.ContentConfig{GroupVersion: testapi.Groups[v1.GroupName].GroupVersion()}})
	ns := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-namespace",
			ClusterName: "cluster-name-to-ignore",
		},
	}
	nsNew, err := client.Core().Namespaces().Create(&ns)
	assert.Nil(t, err)
	assert.Equal(t, ns.Name, nsNew.Name)
	assert.Empty(t, nsNew.ClusterName)

	nsNew, err = client.Core().Namespaces().Update(&ns)
	assert.Nil(t, err)
	assert.Equal(t, ns.Name, nsNew.Name)
	assert.Empty(t, nsNew.ClusterName)
}
