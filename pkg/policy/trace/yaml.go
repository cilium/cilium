// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package trace

import (
	"bytes"
	"fmt"
	"io"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	appsv1beta1 "k8s.io/api/apps/v1beta1"
	appsv1beta2 "k8s.io/api/apps/v1beta2"
	corev1 "k8s.io/api/core/v1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/client-go/kubernetes/scheme"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
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

	byteArr, err := io.ReadAll(reader)
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
		switch o := obj.(type) {
		// TODO: Remove once 1.16 becomes minimum supported version
		case *extensionsv1beta1.Deployment:
			yamlLabels = append(yamlLabels, generateLabels(o.Namespace, o.Spec.Template.Labels)...)
		// TODO: Remove once 1.16 becomes minimum supported version
		case *appsv1beta1.Deployment:
			yamlLabels = append(yamlLabels, generateLabels(o.Namespace, o.Spec.Template.Labels)...)
		// TODO: Remove once 1.16 becomes minimum supported version
		case *appsv1beta2.Deployment:
			yamlLabels = append(yamlLabels, generateLabels(o.Namespace, o.Spec.Template.Labels)...)
		case *appsv1.Deployment:
			yamlLabels = append(yamlLabels, generateLabels(o.Namespace, o.Spec.Template.Labels)...)
		case *corev1.ReplicationController:
			yamlLabels = append(yamlLabels, generateLabels(o.Namespace, o.Spec.Template.Labels)...)
		// TODO: Remove once 1.16 becomes minimum supported version
		case *extensionsv1beta1.ReplicaSet:
			yamlLabels = append(yamlLabels, generateLabels(o.Namespace, o.Spec.Template.Labels)...)
		// TODO: Remove once 1.16 becomes minimum supported version
		case *appsv1beta2.ReplicaSet:
			yamlLabels = append(yamlLabels, generateLabels(o.Namespace, o.Spec.Template.Labels)...)
		case *appsv1.ReplicaSet:
			yamlLabels = append(yamlLabels, generateLabels(o.Namespace, o.Spec.Template.Labels)...)
		default:
			return nil, fmt.Errorf("unsupported type provided in YAML file: %T", obj)
		}
		splitYamlLabels = append(splitYamlLabels, yamlLabels)
	}
	return splitYamlLabels, nil
}

func generateLabels(namespace string, labelsMap map[string]string) []string {
	var labelsArr []string
	temp := namespace
	if temp == "" {
		temp = DefaultNamespace
	}
	labelsArr = append(labelsArr, labels.GenerateK8sLabelString(k8sConst.PodNamespaceLabel, temp))
	for k, v := range labelsMap {
		labelsArr = append(labelsArr, labels.GenerateK8sLabelString(k, v))
	}
	return labelsArr
}
