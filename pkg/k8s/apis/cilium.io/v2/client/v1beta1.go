// Copyright 2017-2020 Authors of Cilium
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

package client

import (
	"context"
	goerrors "errors"
	"fmt"
	"time"

	k8sconstv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/versioncheck"
	"github.com/sirupsen/logrus"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	v1beta1client "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func createUpdateV1beta1CRD(
	scopedLog *logrus.Entry,
	client v1beta1client.CustomResourceDefinitionsGetter,
	crdName string,
	crd *apiextensionsv1.CustomResourceDefinition,
	poller poller,
) error {
	v1beta1CRD, err := convertToV1Beta1CRD(crd)
	if err != nil {
		return err
	}

	clusterCRD, err := client.CustomResourceDefinitions().Get(
		context.TODO(),
		v1beta1CRD.ObjectMeta.Name,
		metav1.GetOptions{})
	if errors.IsNotFound(err) {
		scopedLog.Info("Creating CRD (CustomResourceDefinition)...")

		clusterCRD, err = client.CustomResourceDefinitions().Create(
			context.TODO(),
			v1beta1CRD,
			metav1.CreateOptions{})
		// This occurs when multiple agents race to create the CRD. Since another has
		// created it, it will also update it, hence the non-error return.
		if errors.IsAlreadyExists(err) {
			return nil
		}
	}
	if err != nil {
		return err
	}

	if err := updateV1beta1CRD(scopedLog, v1beta1CRD, clusterCRD, client, poller); err != nil {
		return err
	}
	if err := waitForV1beta1CRD(scopedLog, crdName, clusterCRD, client, poller); err != nil {
		return err
	}

	scopedLog.Info("CRD (CustomResourceDefinition) is installed and up-to-date")

	return nil
}

func needsUpdateV1beta1(clusterCRD *apiextensionsv1beta1.CustomResourceDefinition) bool {
	if clusterCRD.Spec.Validation == nil {
		// no validation detected
		return true
	}
	v, ok := clusterCRD.Labels[k8sconstv2.CustomResourceDefinitionSchemaVersionKey]
	if !ok {
		// no schema version detected
		return true
	}

	clusterVersion, err := versioncheck.Version(v)
	if err != nil || clusterVersion.LT(comparableCRDSchemaVersion) {
		// version in cluster is either unparsable or smaller than current version
		return true
	}

	return false
}

func convertToV1Beta1CRD(crd *apiextensionsv1.CustomResourceDefinition) (*apiextensionsv1beta1.CustomResourceDefinition, error) {
	internalCRD := new(apiextensions.CustomResourceDefinition)
	v1beta1CRD := new(apiextensionsv1beta1.CustomResourceDefinition)

	if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
		crd,
		internalCRD,
		nil,
	); err != nil {
		return nil, fmt.Errorf("unable to convert v1 CRD to internal representation: %v", err)
	}

	if err := apiextensionsv1beta1.Convert_apiextensions_CustomResourceDefinition_To_v1beta1_CustomResourceDefinition(
		internalCRD,
		v1beta1CRD,
		nil,
	); err != nil {
		return nil, fmt.Errorf("unable to convert internally represented CRD to v1beta1: %v", err)
	}

	return v1beta1CRD, nil
}

func updateV1beta1CRD(
	scopedLog *logrus.Entry,
	crd, clusterCRD *apiextensionsv1beta1.CustomResourceDefinition,
	client v1beta1client.CustomResourceDefinitionsGetter,
	poller poller,
) error {
	scopedLog.Debug("Checking if CRD (CustomResourceDefinition) needs update...")

	if crd.Spec.Validation != nil && needsUpdateV1beta1(clusterCRD) {
		scopedLog.Info("Updating CRD (CustomResourceDefinition)...")

		// Update the CRD with the validation schema.
		err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
			var err error
			if clusterCRD, err = client.CustomResourceDefinitions().Get(
				context.TODO(),
				crd.ObjectMeta.Name,
				metav1.GetOptions{},
			); err != nil {
				return false, err
			}

			// This seems too permissive but we only get here if the version is
			// different per needsUpdate above. If so, we want to update on any
			// validation change including adding or removing validation.
			if needsUpdateV1beta1(clusterCRD) {
				scopedLog.Debug("CRD validation is different, updating it...")

				clusterCRD.ObjectMeta.Labels = crd.ObjectMeta.Labels
				clusterCRD.Spec = crd.Spec

				_, err := client.CustomResourceDefinitions().Update(
					context.TODO(),
					clusterCRD,
					metav1.UpdateOptions{})
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

	return nil
}

func waitForV1beta1CRD(
	scopedLog *logrus.Entry,
	crdName string,
	crd *apiextensionsv1beta1.CustomResourceDefinition,
	client v1beta1client.CustomResourceDefinitionsGetter,
	poller poller,
) error {
	scopedLog.Debug("Waiting for CRD (CustomResourceDefinition) to be available...")

	err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1beta1.Established:
				if cond.Status == apiextensionsv1beta1.ConditionTrue {
					return true, nil
				}
			case apiextensionsv1beta1.NamesAccepted:
				if cond.Status == apiextensionsv1beta1.ConditionFalse {
					err := goerrors.New(cond.Reason)
					scopedLog.WithError(err).Error("Name conflict for CRD")
					return false, err
				}
			}
		}

		var err error
		if crd, err = client.CustomResourceDefinitions().Get(
			context.TODO(),
			crd.ObjectMeta.Name,
			metav1.GetOptions{}); err != nil {
			return false, err
		}
		return false, err
	})
	if err != nil {
		return fmt.Errorf("error occurred waiting for CRD: %w", err)
	}

	return nil
}
