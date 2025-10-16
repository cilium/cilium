// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"fmt"
	"log/slog"
	"strconv"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	mcsapicrd "sigs.k8s.io/mcs-api/config/crd"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s/apis/crdhelpers"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// createCustomResourceDefinitions creates our CRD objects in the Kubernetes
// cluster.
func createCustomResourceDefinitions(logger *slog.Logger, clientset apiextensionsclient.Interface) error {
	for _, crdName := range []string{mcsapiv1alpha1.ServiceImportVersionedName, mcsapiv1alpha1.ServiceExportVersionedName} {
		if err := createCRD(logger, clientset, crdName); err != nil {
			return fmt.Errorf("Unable to create custom resource definition: %w", err)
		}
	}

	return nil
}

// getPregeneratedCRD returns the pregenerated CRD based on the requested CRD
// name. This function retrieves CRDs from the binary form.
func getPregeneratedCRD(logger *slog.Logger, crdName string) apiextensionsv1.CustomResourceDefinition {
	var (
		err      error
		crdBytes []byte
	)

	switch crdName {
	case mcsapiv1alpha1.ServiceImportVersionedName:
		crdBytes = mcsapicrd.ServiceImportCRD
	case mcsapiv1alpha1.ServiceExportVersionedName:
		crdBytes = mcsapicrd.ServiceExportCRD
	default:
		logging.Fatal(logger, "Pregenerated CRD does not exist", logfields.CRDName, crdName)
	}

	crd := apiextensionsv1.CustomResourceDefinition{}
	err = yaml.Unmarshal(crdBytes, &crd)
	if err != nil {
		logging.Fatal(
			logger,
			"Error unmarshalling pregenerated CRD",
			logfields.Error, err,
			logfields.CRDName, crdName,
		)
	}
	return crd
}

// createCRD creates and updates a CRD.
// It should be called on operator startup but is idempotent and safe to call again.
func createCRD(logger *slog.Logger, clientset apiextensionsclient.Interface, crdVersionedName string) error {
	crd := getPregeneratedCRD(logger, crdVersionedName)

	return crdhelpers.CreateUpdateCRD(
		logger,
		clientset,
		&crd,
		crdhelpers.NewDefaultPoller(),
		needsUpdateMCS,
	)
}

func needsUpdateMCS(targetCRD, currentCRD *apiextensionsv1.CustomResourceDefinition) (bool, error) {
	if currentCRD.Spec.Versions[0].Schema == nil {
		// no validation detected
		return true, nil
	}

	// release version check
	v, ok := currentCRD.Labels[mcsapicrd.ReleaseVersionLabel]
	if !ok {
		// no schema version detected
		return true, nil
	}
	currentVersion, err := versioncheck.Version(v)
	version, errTarget := versioncheck.Version(targetCRD.Labels[mcsapicrd.ReleaseVersionLabel])
	if errTarget != nil {
		return false, fmt.Errorf("invalid release version label on CRD %s: %s", targetCRD.Name, targetCRD.Labels[mcsapicrd.ReleaseVersionLabel])
	}

	if err != nil || currentVersion.LT(version) {
		// version in cluster is either unparsable or smaller than current version
		return true, nil
	}

	// CRD Revision check
	rev, ok := currentCRD.Labels[mcsapicrd.CustomResourceDefinitionSchemaRevisionLabel]
	if !ok {
		// no CRD revision detected
		return true, nil
	}
	currentRevision, err := strconv.Atoi(rev)
	revision, errTarget := strconv.Atoi(targetCRD.Labels[mcsapicrd.CustomResourceDefinitionSchemaRevisionLabel])
	if errTarget != nil {
		return false, fmt.Errorf("invalid CRD revision label on CRD %s: %s", targetCRD.Name, targetCRD.Labels[mcsapicrd.CustomResourceDefinitionSchemaRevisionLabel])
	}

	if err != nil || currentRevision < revision {
		// crd revision in cluster is either unparsable or smaller than current version
		return true, nil
	}

	return false, nil
}
