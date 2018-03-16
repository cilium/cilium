// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trace

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis"
	"github.com/cilium/cilium/pkg/labels"

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/client-go/kubernetes/scheme"
)

const (
	// DefaultNamespace represents the default Kubernetes namespace.
	DefaultNamespace = "default"
)

// GetLabelsFromYaml iterates through the provided YAML file and for each
// section in the YAML, returns the labels or an error if the labels could not
// be parsed.
func GetLabelsFromYaml(file string) ([][]string, error) {
	reader, err := os.Open(file)

	if err != nil {
		return nil, err
	}
	defer reader.Close()

	byteArr, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	splitYamlLabels := [][]string{}
	yamlDocs := bytes.Split(byteArr, []byte("---"))
	for _, v := range yamlDocs {
		yamlLabels := []string{}

		// Ignore empty documents, e.g., file starting with --- or ---\n
		if len(v) < 2 {
			continue
		}

		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(v, nil, nil)
		if err != nil {
			return nil, err
		}
		switch obj.(type) {
		case *v1beta1.Deployment:
			deployment := obj.(*v1beta1.Deployment)
			var ns string
			if deployment.Namespace != "" {
				ns = deployment.Namespace
			} else {
				ns = DefaultNamespace
			}
			yamlLabels = append(yamlLabels, labels.GenerateK8sLabelString(k8sConst.PodNamespaceLabel, ns))

			for k, v := range deployment.Spec.Template.Labels {
				yamlLabels = append(yamlLabels, labels.GenerateK8sLabelString(k, v))
			}
		case *v1.ReplicationController:
			controller := obj.(*v1.ReplicationController)
			var ns string
			if controller.Namespace != "" {
				ns = controller.Namespace
			} else {
				ns = DefaultNamespace
			}
			yamlLabels = append(yamlLabels, labels.GenerateK8sLabelString(k8sConst.PodNamespaceLabel, ns))

			for k, v := range controller.Spec.Template.Labels {
				yamlLabels = append(yamlLabels, labels.GenerateK8sLabelString(k, v))
			}
		case *v1beta1.ReplicaSet:
			rep := obj.(*v1beta1.ReplicaSet)
			var ns string
			if rep.Namespace != "" {
				ns = rep.Namespace
			} else {
				ns = DefaultNamespace
			}
			yamlLabels = append(yamlLabels, labels.GenerateK8sLabelString(k8sConst.PodNamespaceLabel, ns))

			for k, v := range rep.Spec.Template.Labels {
				yamlLabels = append(yamlLabels, labels.GenerateK8sLabelString(k, v))
			}
		default:
			return nil, fmt.Errorf("unsupported type provided in YAML file: %T", obj)
		}
		splitYamlLabels = append(splitYamlLabels, yamlLabels)
	}
	return splitYamlLabels, nil
}
