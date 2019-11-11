// Copyright 2016-2019 Authors of Cilium
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

package k8s

import (
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IsStsPod determines if the given pod belongs to a sts by retrieving the
// metadata from k8s API
func IsStsPod(fullPodName string) (bool, error) {
	// extract sts name
	items := strings.Split(fullPodName, "/")
	if len(items) != 2 {
		log.Infof("%s is not sts pod: contains more than 1 slashes", fullPodName)
		return false, nil
	}

	namespace, podName := items[0], items[1]
	i := strings.LastIndex(podName, "-")
	if i < 1 {
		log.Infof("%s is not sts pod: contains more than 1 dashes", fullPodName)
		return false, nil
	}

	stsName := podName[:i]
	if _, err := strconv.Atoi(podName[i+1:]); err != nil {
		log.Infof("%s is not sts pod: index not found", fullPodName)
		return false, nil
	}

	// call K8S API
	_, err := Client().AppsV1().StatefulSets(namespace).Get(stsName,
		metav1.GetOptions{})
	if err != nil {
		switch err.Error() {
		case `statefulsets.apps "` + stsName + `" not found`:
			log.Infof("%s is not sts pod: sts not found in k8s", fullPodName)
			return false, nil
		default:
			return false, err
		}
	}

	log.Infof("pod %s belongs to a sts", fullPodName)
	return true, nil
}

// IsStsPodDeleted determines if the pod is deleted from the node by retrieving
// the metadata in k8s API
// pod name format: <namespace>/<stsName>-<podIndex>
func IsStsPodDeleted(nodeName string, fullPodName string) (bool, error) {
	// extract sts name
	items := strings.Split(fullPodName, "/")
	if len(items) != 2 {
		return false, fmt.Errorf("unexpected fullPodName %s", fullPodName)
	}

	ns, podName := items[0], items[1]
	i := strings.LastIndex(podName, "-")
	if i < 1 {
		return false, fmt.Errorf("mal-formed pod name %s", podName)
	}

	stsName := podName[:i]
	podIndex, err := strconv.Atoi(podName[i+1:])
	if err != nil {
		return false, err
	}

	// get info through K8S API
	log.Infof("check if %s/%s still exists in apiserver", ns, stsName)
	sts, err := Client().AppsV1().StatefulSets(ns).Get(stsName,
		metav1.GetOptions{})
	if err != nil {
		switch err.Error() {
		case `statefulsets.apps "` + stsName + `" not found`:
			log.Infof("Statefulset %s has been deleted from K8S", fullPodName)
			return true, nil
		default:
			return false, err
		}
	}

	const (
		foreground = "foregroundDeletion"
	)

	// If the resource is being deleted with PropagationPolicy foreground,
	// the replicas field will remain unchanged, so we need to handle such cases here.
	finalizers := (*sts).ObjectMeta.Finalizers
	if len(finalizers) > 0 {
		log.Infof("PropagationPolicy case")
		propagationPolicy := finalizers[0]
		if propagationPolicy == foreground {
			log.Infof("PropagationPolicy == foreground case")
			return true, nil
		}
	}

	replicas := int(*sts.Spec.Replicas)
	log.Infof("sts replicas: %d, pod index: %d", replicas, podIndex)
	if replicas > 0 && podIndex < replicas {
		return false, nil // valid index, pod still in sts replicas
	}

	return true, nil // pod truly deleted from sts replicas
}

// GetNodeStsPods calls K8S API and returns all sts pods on this node
func GetNodeStsPods(nodeName string) ([]string, error) {
	podNames := []string{}
	options := metav1.ListOptions{FieldSelector: "spec.nodeName=" + nodeName}
	podList, err := Client().CoreV1().Pods("").List(options)
	if err != nil {
		return podNames, err
	}

	for _, p := range podList.Items {
		namespace := p.ObjectMeta.Namespace
		podName := p.ObjectMeta.Name
		owners := p.ObjectMeta.OwnerReferences

		isSts := false
		for _, r := range owners {
			if r.Kind == "StatefulSet" {
				name := namespace + "/" + podName
				podNames = append(podNames, name)
				isSts = true
				break
			}
		}

		if isSts {
			continue
		}

		log.Infof("Skip pod %s, owners %v\n", podName, owners)
	}

	return podNames, nil
}
