// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

const mandatoryCategory = "cilium"

type checkCRDFunc func(*crdv1.CustomResourceDefinition) error

var allChecks = []checkCRDFunc{
	checkForCategory,
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal(fmt.Sprintf("usage: %s <path>", os.Args[0]))
	}

	_ = crdv1.AddToScheme(scheme.Scheme)

	if err := filepath.Walk(os.Args[1], func(path string, info os.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}

		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}

		fileContent, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(fileContent, nil, nil)
		if err != nil {
			return err
		}

		crd, ok := obj.(*crdv1.CustomResourceDefinition)
		if !ok {
			return nil
		}

		for _, f := range allChecks {
			if err = f(crd); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		log.Fatal(err)
	}
}

func checkForCategory(crd *crdv1.CustomResourceDefinition) error {
	if len(crd.Spec.Names.Categories) == 0 || !sliceContains(crd.Spec.Names.Categories, mandatoryCategory) {
		return fmt.Errorf("category %s missing for %s", mandatoryCategory, crd.GetName())
	}

	return nil
}

func sliceContains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}
