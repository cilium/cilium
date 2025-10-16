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
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// registerCRDs registers MCS-API CRDs with the K8s apiserver.
func registerCRDs(logger *slog.Logger, clientset client.Clientset) error {
	if err := createCustomResourceDefinitions(logger, clientset); err != nil {
		return fmt.Errorf("Unable to create custom resource definition: %w", err)
	}

	return nil
}

// createCustomResourceDefinitions creates our CRD objects in the Kubernetes
// cluster.
func createCustomResourceDefinitions(logger *slog.Logger, clientset apiextensionsclient.Interface) error {
	for _, crdName := range []string{mcsapiv1alpha1.ServiceImportVersionedName, mcsapiv1alpha1.ServiceExportVersionedName} {
		if err := createCRD(logger, crdName)(clientset); err != nil {
			return err
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

	logAttr := slog.String("crdName", crdName)

	switch crdName {
	case mcsapiv1alpha1.ServiceImportVersionedName:
		crdBytes = mcsapicrd.ServiceImportCRD
	case mcsapiv1alpha1.ServiceExportVersionedName:
		crdBytes = mcsapicrd.ServiceExportCRD
	default:
		logging.Fatal(logger, "Pregenerated CRD does not exist", logAttr)
	}

	crd := apiextensionsv1.CustomResourceDefinition{}
	err = yaml.Unmarshal(crdBytes, &crd)
	if err != nil {
		logging.Fatal(
			logger,
			"Error unmarshalling pregenerated CRD",
			slog.Any(logfields.Error, err),
			logAttr,
		)
	}
	return crd
}

// createCRD creates and updates a CRD.
// It should be called on operator startup but is idempotent and safe to call again.
func createCRD(logger *slog.Logger, crdVersionedName string) func(clientset apiextensionsclient.Interface) error {
	return func(clientset apiextensionsclient.Interface) error {
		crd := getPregeneratedCRD(logger, crdVersionedName)

		return crdhelpers.CreateUpdateCRD(
			logger,
			clientset,
			&crd,
			crdhelpers.NewDefaultPoller(),
			NeedsUpdateMCS,
		)
	}
}

func NeedsUpdateMCS(crd, clusterCRD *apiextensionsv1.CustomResourceDefinition) bool {
	if clusterCRD.Spec.Versions[0].Schema == nil {
		// no validation detected
		return true
	}

	// release version check
	v, ok := clusterCRD.Labels[mcsapicrd.ReleaseVersionLabel]
	if !ok {
		// no schema version detected
		return true
	}
	clusterVersion, err := versioncheck.Version(v)
	version := versioncheck.MustVersion(crd.Labels[mcsapicrd.ReleaseVersionLabel])
	if err != nil || clusterVersion.LT(version) {
		// version in cluster is either unparsable or smaller than current version
		return true
	}

	// CRD Revision check
	rev, ok := clusterCRD.Labels[mcsapicrd.CustomResourceDefinitionSchemaRevisionLabel]
	if !ok {
		// no CRD revision detected
		return true
	}
	clusterRevision, err := strconv.Atoi(rev)
	revision, errAtoi := strconv.Atoi(crd.Labels[mcsapicrd.CustomResourceDefinitionSchemaRevisionLabel])
	if errAtoi != nil {
		panic(fmt.Sprintf("invalid CRD revision label on CRD %s: %s", crd.Name, crd.Labels[mcsapicrd.CustomResourceDefinitionSchemaRevisionLabel]))
	}
	if err != nil || clusterRevision < revision {
		// crd revision in cluster is either unparsable or smaller than current version
		return true
	}

	return false
}
