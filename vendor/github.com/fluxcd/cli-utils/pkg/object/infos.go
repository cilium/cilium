// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/cli-runtime/pkg/resource"
	"sigs.k8s.io/kustomize/kyaml/kio/kioutil"
)

// InfosToObjMetas returns object metadata (ObjMetadata) for the
// passed objects (infos); returns an error if one occurs.
func InfosToObjMetas(infos []*resource.Info) ([]ObjMetadata, error) {
	objMetas := make([]ObjMetadata, 0, len(infos))
	for _, info := range infos {
		objMeta, err := InfoToObjMeta(info)
		if err != nil {
			return nil, err
		}
		objMetas = append(objMetas, objMeta)
	}
	return objMetas, nil
}

// InfoToObjMeta takes information from the provided info and
// returns an ObjMetadata that identifies the resource.
func InfoToObjMeta(info *resource.Info) (ObjMetadata, error) {
	if info == nil || info.Object == nil {
		return ObjMetadata{}, fmt.Errorf("attempting to transform info, but it is empty")
	}
	id := ObjMetadata{
		Namespace: info.Namespace,
		Name:      info.Name,
		GroupKind: info.Object.GetObjectKind().GroupVersionKind().GroupKind(),
	}
	return id, nil
}

// InfoToUnstructured transforms the passed info object into unstructured format.
func InfoToUnstructured(info *resource.Info) *unstructured.Unstructured {
	return info.Object.(*unstructured.Unstructured)
}

// UnstructuredToInfo transforms the passed Unstructured object into Info format,
// or an error if one occurs.
func UnstructuredToInfo(obj *unstructured.Unstructured) (*resource.Info, error) {
	// make a copy of the input object to avoid modifying the input
	obj = obj.DeepCopy()

	annos := obj.GetAnnotations()

	source := "unstructured"
	path, ok := annos[kioutil.PathAnnotation]
	if ok {
		source = path
	}
	StripKyamlAnnotations(obj)

	return &resource.Info{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		Source:    source,
		Object:    obj,
	}, nil
}

// InfosToUnstructureds transforms the passed objects in Info format to Unstructured.
func InfosToUnstructureds(infos []*resource.Info) []*unstructured.Unstructured {
	var objs []*unstructured.Unstructured
	for _, info := range infos {
		objs = append(objs, InfoToUnstructured(info))
	}
	return objs
}

// UnstructuredsToInfos transforms the passed Unstructured objects into Info format
// or an error if one occurs.
func UnstructuredsToInfos(objs []*unstructured.Unstructured) ([]*resource.Info, error) {
	var infos []*resource.Info
	for _, obj := range objs {
		inf, err := UnstructuredToInfo(obj)
		if err != nil {
			return infos, err
		}
		infos = append(infos, inf)
	}
	return infos, nil
}
