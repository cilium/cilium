// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package crdhelpers

import (
	"context"
	goerrors "errors"
	"fmt"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	v1client "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// subsysK8s is the value for logfields.LogSubsys
const subsysK8s = "k8s"

// log is the k8s package logger object.
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)

// CreateUpdateCRD ensures the CRD object is installed into the K8s cluster. It
// will create or update the CRD and its validation schema as necessary. This
// function only accepts v1 CRD objects.
func CreateUpdateCRD(
	clientset apiextensionsclient.Interface,
	crd *apiextensionsv1.CustomResourceDefinition,
	poller poller,
	crdSchemaVersionLabelKey string,
	minCRDSchemaVersion semver.Version,
) error {
	scopedLog := log.WithField("name", crd.Name)

	v1CRDClient := clientset.ApiextensionsV1()
	clusterCRD, err := v1CRDClient.CustomResourceDefinitions().Get(
		context.TODO(),
		crd.ObjectMeta.Name,
		metav1.GetOptions{})
	if errors.IsNotFound(err) {
		scopedLog.Info("Creating CRD (CustomResourceDefinition)...")

		clusterCRD, err = v1CRDClient.CustomResourceDefinitions().Create(
			context.TODO(),
			crd,
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

	if err := updateV1CRD(scopedLog, crd, clusterCRD, v1CRDClient, poller, crdSchemaVersionLabelKey, minCRDSchemaVersion); err != nil {
		return err
	}
	if err := waitForV1CRD(scopedLog, clusterCRD, v1CRDClient, poller); err != nil {
		return err
	}

	scopedLog.Info("CRD (CustomResourceDefinition) is installed and up-to-date")

	return nil
}

func needsUpdateV1(
	clusterCRD *apiextensionsv1.CustomResourceDefinition,
	crdSchemaVersionLabelKey string,
	minCRDSchemaVersion semver.Version,
) bool {
	if clusterCRD.Spec.Versions[0].Schema == nil {
		// no validation detected
		return true
	}
	v, ok := clusterCRD.Labels[crdSchemaVersionLabelKey]
	if !ok {
		// no schema version detected
		return true
	}

	clusterVersion, err := versioncheck.Version(v)
	if err != nil || clusterVersion.LT(minCRDSchemaVersion) {
		// version in cluster is either unparsable or smaller than current version
		return true
	}

	return false
}

func updateV1CRD(
	scopedLog *logrus.Entry,
	crd, clusterCRD *apiextensionsv1.CustomResourceDefinition,
	client v1client.CustomResourceDefinitionsGetter,
	poller poller,
	crdSchemaVersionLabelKey string,
	minCRDSchemaVersion semver.Version,
) error {
	scopedLog.Debug("Checking if CRD (CustomResourceDefinition) needs update...")

	if crd.Spec.Versions[0].Schema != nil && needsUpdateV1(clusterCRD, crdSchemaVersionLabelKey, minCRDSchemaVersion) {
		scopedLog.Info("Updating CRD (CustomResourceDefinition)...")

		// Update the CRD with the validation schema.
		err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
			var err error
			clusterCRD, err = client.CustomResourceDefinitions().Get(
				context.TODO(),
				crd.ObjectMeta.Name,
				metav1.GetOptions{})
			if err != nil {
				return false, err
			}

			// This seems too permissive but we only get here if the version is
			// different per needsUpdate above. If so, we want to update on any
			// validation change including adding or removing validation.
			if needsUpdateV1(clusterCRD, crdSchemaVersionLabelKey, minCRDSchemaVersion) {
				scopedLog.Debug("CRD validation is different, updating it...")

				clusterCRD.ObjectMeta.Labels = crd.ObjectMeta.Labels
				clusterCRD.Spec = crd.Spec

				// Even though v1 CRDs omit this field by default (which also
				// means it's false) it is still carried over from the previous
				// CRD. Therefore, we must set this to false explicitly because
				// the apiserver will carry over the old value (true).
				clusterCRD.Spec.PreserveUnknownFields = false

				_, err := client.CustomResourceDefinitions().Update(
					context.TODO(),
					clusterCRD,
					metav1.UpdateOptions{})
				switch {
				case errors.IsConflict(err): // Occurs as Operators race to update CRDs.
					scopedLog.WithError(err).
						Debug("The CRD update was based on an older version, retrying...")
					return false, nil
				case err == nil:
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

func waitForV1CRD(
	scopedLog *logrus.Entry,
	crd *apiextensionsv1.CustomResourceDefinition,
	client v1client.CustomResourceDefinitionsGetter,
	poller poller,
) error {
	scopedLog.Debug("Waiting for CRD (CustomResourceDefinition) to be available...")

	err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1.Established:
				if cond.Status == apiextensionsv1.ConditionTrue {
					return true, nil
				}
			case apiextensionsv1.NamesAccepted:
				if cond.Status == apiextensionsv1.ConditionFalse {
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

// poller is an interface that abstracts the polling logic when dealing with
// CRD changes / updates to the apiserver. The reason this exists is mainly for
// unit-testing.
type poller interface {
	Poll(interval, duration time.Duration, conditionFn func() (bool, error)) error
}

func NewDefaultPoller() defaultPoll {
	return defaultPoll{}
}

type defaultPoll struct{}

func (p defaultPoll) Poll(
	interval, duration time.Duration,
	conditionFn func() (bool, error),
) error {
	return wait.Poll(interval, duration, conditionFn)
}
