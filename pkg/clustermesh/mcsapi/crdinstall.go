// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"fmt"
	"log/slog"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	mcsapicrd "sigs.k8s.io/mcs-api/config/crd"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	"sigs.k8s.io/yaml"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumclient "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/cilium/pkg/k8s/apis/crdhelpers"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	// customResourceDefinitionSchemaVersion is semver-conformant version of CRD schema
	// Used to determine if CRD needs to be updated in cluster
	customResourceDefinitionSchemaVersion = "1.0.0"
)

// registerCRDs registers MCS-API CRDs with the K8s apiserver.
func registerCRDs(logger *slog.Logger, clientset client.Clientset) error {
	if err := createCustomResourceDefinitions(logger, clientset); err != nil {
		return fmt.Errorf("Unable to create custom resource definition: %w", err)
	}

	return nil
}

// customResourceDefinitionList returns a map of CRDs
func customResourceDefinitionList() map[string]*ciliumclient.CRDList {
	return map[string]*ciliumclient.CRDList{
		synced.CRDResourceName(mcsapiv1alpha1.ServiceImportFullName): {
			Name:     mcsapiv1alpha1.ServiceImportVersionedName,
			FullName: mcsapiv1alpha1.ServiceImportFullName,
		},
		synced.CRDResourceName(mcsapiv1alpha1.ServiceExportFullName): {
			Name:     mcsapiv1alpha1.ServiceExportVersionedName,
			FullName: mcsapiv1alpha1.ServiceExportFullName,
		},
	}
}

// createCustomResourceDefinitions creates our CRD objects in the Kubernetes
// cluster.
func createCustomResourceDefinitions(logger *slog.Logger, clientset apiextensionsclient.Interface) error {
	crds := customResourceDefinitionList()

	for _, r := range synced.MCSAPIResourceNames() {
		if crd, ok := crds[r]; ok {
			if err := createCRD(logger, crd.Name, crd.FullName)(clientset); err != nil {
				return err
			}
		} else {
			logging.Fatal(logger, fmt.Sprintf("Unknown resource %s. Please update pkg/clustermesh/mcsapi/crdinstall.go to understand this type.", r))
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
	crd.Labels = map[string]string{
		k8sconst.CustomResourceDefinitionSchemaVersionKey: customResourceDefinitionSchemaVersion,
	}

	return crd
}

// createCRD creates and updates a CRD.
// It should be called on agent startup but is idempotent and safe to call again.
func createCRD(logger *slog.Logger, crdVersionedName string, crdMetaName string) func(clientset apiextensionsclient.Interface) error {
	return func(clientset apiextensionsclient.Interface) error {
		crd := getPregeneratedCRD(logger, crdVersionedName)

		return crdhelpers.CreateUpdateCRD(
			logger,
			clientset,
			&crd,
			crdhelpers.NewDefaultPoller(),
			k8sconst.CustomResourceDefinitionSchemaVersionKey,
			versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
		)
	}
}
