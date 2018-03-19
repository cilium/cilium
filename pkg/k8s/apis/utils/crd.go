// Copyright 2018 Authors of Cilium
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

package utils

import (
	goerrors "errors"
	"fmt"
	"time"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/hashicorp/go-version"
)

const (
	// CustomResourceDefinitionSchemaVersionKey is key to label which holds the CRD schema version
	CustomResourceDefinitionSchemaVersionKey = "io.cilium.k8s.crd.schema.version"
)

// CreateUpdateCRD ensures the CRD object is installed into the k8s cluster. It
// will create or update the CRD and its validation when needed.
// Note: label of key CustomResourceDefinitionSchemaVersionKey must be on the
// CRD for update checks to work. The value is expected to be semver compliant.
func CreateUpdateCRD(clientset apiextensionsclient.Interface, CRDName string, crd *apiextensionsv1beta1.CustomResourceDefinition) error {
	scopedLog := log.WithField("name", CRDName)

	CRDVersion, found := crd.ObjectMeta.Labels[CustomResourceDefinitionSchemaVersionKey]
	if !found {
		return fmt.Errorf("Missing CRD version label %s", CustomResourceDefinitionSchemaVersionKey)
	}

	clusterCRD, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(crd.ObjectMeta.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		scopedLog.Info("Creating CRD (CustomResourceDefinition)...")
		clusterCRD, err = clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
		// This occurs when multiple agents race to create the CRD. Since another has
		// created it, it will also update it, hence the non-error return.
		if errors.IsAlreadyExists(err) {
			return nil
		}
	}
	if err != nil {
		return err
	}

	scopedLog.Debug("Checking if CRD (CustomResourceDefinition) needs update...")
	if needsUpdate(clusterCRD, CRDVersion) {
		scopedLog.Info("Updating CRD (CustomResourceDefinition)...")
		// Update the CRD with the validation schema.
		err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
			clusterCRD, err = clientset.ApiextensionsV1beta1().
				CustomResourceDefinitions().Get(crd.ObjectMeta.Name, metav1.GetOptions{})

			if err != nil {
				return false, err
			}

			// This seems too permissive but we only get here if the version is
			// different per needsUpdate above. If so, we want to update on any
			// validation change including adding or removing validation.
			if needsUpdate(clusterCRD, CRDVersion) {
				scopedLog.Debug("CRD validation is different, updating it...")
				clusterCRD.ObjectMeta.Labels = crd.ObjectMeta.Labels
				clusterCRD.Spec = crd.Spec
				_, err = clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Update(clusterCRD)
				if err == nil {
					return true, nil
				}
				scopedLog.WithError(err).Debug("Unable to update CRD validation")
				return false, err
			}

			return true, nil
		})
		if err != nil {
			scopedLog.WithError(err).Error("Unable to update CRD")
			return err
		}
	}

	// wait for the CRD to be established
	scopedLog.Debug("Waiting for CRD (CustomResourceDefinition) to be available...")
	err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		crd, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(crd.ObjectMeta.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1beta1.Established:
				if cond.Status == apiextensionsv1beta1.ConditionTrue {
					return true, err
				}
			case apiextensionsv1beta1.NamesAccepted:
				if cond.Status == apiextensionsv1beta1.ConditionFalse {
					scopedLog.WithError(goerrors.New(cond.Reason)).Error("Name conflict for CRD")
					return false, err
				}
			}
		}
		return false, err
	})
	if err != nil {
		deleteErr := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(crd.ObjectMeta.Name, nil)
		if deleteErr != nil {
			return fmt.Errorf("unable to delete k8s %s CRD %s. Deleting CRD due: %s", CRDName, deleteErr, err)
		}
		return err
	}

	scopedLog.Info("CRD (CustomResourceDefinition) is installed and up-to-date")
	return nil
}

func needsUpdate(clusterCRD *apiextensionsv1beta1.CustomResourceDefinition, CRDVersion string) bool {
	if clusterCRD.Spec.Validation == nil {
		// no validation detected
		return true
	}
	v, ok := clusterCRD.Labels[CustomResourceDefinitionSchemaVersionKey]
	if !ok {
		// no schema version detected
		return true
	}
	clusterVersion, err := version.NewVersion(v)
	comparableCRDSchemaVersion := version.Must(version.NewVersion(CRDVersion))
	if err != nil || clusterVersion.LessThan(comparableCRDSchemaVersion) {
		// version in cluster is either unparsable or smaller than current version
		return true
	}
	return false
}

// Delete CRD removes the CRD by name, checking for existence first
func DeleteCRD(clientset apiextensionsclient.Interface, CRDName string) error {
	_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(CRDName, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		return nil

	case err != nil:
		return err
	}

	zero := int64(0)                                    // because GracePeriodSeconds is a pointer
	deletePropagation := metav1.DeletePropagationOrphan // because this is a string type but k8s wants a pointer
	err = clientset.ApiextensionsV1beta1().
		CustomResourceDefinitions().Delete(CRDName,
		&metav1.DeleteOptions{
			GracePeriodSeconds: &zero,              // immediate deletion
			PropagationPolicy:  &deletePropagation, // dependents deleted in the background
		})
	if err != nil {
		return fmt.Errorf("unable to delete k8s %s CRD %s.", CRDName, err)
	}
	return err
}
