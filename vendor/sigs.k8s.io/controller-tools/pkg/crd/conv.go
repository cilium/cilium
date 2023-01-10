package crd

import (
	"fmt"

	apiextinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	conversionScheme = runtime.NewScheme()
)

func init() {
	if err := apiextinternal.AddToScheme(conversionScheme); err != nil {
		panic("must be able to add internal apiextensions to the CRD conversion Scheme")
	}
	if err := apiext.AddToScheme(conversionScheme); err != nil {
		panic("must be able to add apiextensions/v1 to the CRD conversion Scheme")
	}
	if err := apiextv1beta1.AddToScheme(conversionScheme); err != nil {
		panic("must be able to add apiextensions/v1beta1 to the CRD conversion Scheme")
	}
}

// AsVersion converts a CRD from the canonical internal form (currently v1) to some external form.
func AsVersion(original apiext.CustomResourceDefinition, gv schema.GroupVersion) (runtime.Object, error) {
	// We can use the internal versions an existing conversions from kubernetes, since they're not in k/k itself.
	// This punts the problem of conversion down the road for a future maintainer (or future instance of @directxman12)
	// when we have to support older versions that get removed, or when API machinery decides to yell at us for this
	// questionable decision.
	intVer, err := conversionScheme.ConvertToVersion(&original, apiextinternal.SchemeGroupVersion)
	if err != nil {
		return nil, fmt.Errorf("unable to convert to internal CRD version: %w", err)
	}

	return conversionScheme.ConvertToVersion(intVer, gv)
}

// mergeIdenticalSubresources checks to see if subresources are identical across
// all versions, and if so, merges them into a top-level version.
//
// This assumes you're not using trivial versions.
func mergeIdenticalSubresources(crd *apiextv1beta1.CustomResourceDefinition) {
	subres := crd.Spec.Versions[0].Subresources
	for _, ver := range crd.Spec.Versions {
		if ver.Subresources == nil || !equality.Semantic.DeepEqual(subres, ver.Subresources) {
			// either all nil, or not identical
			return
		}
	}

	// things are identical if we've gotten this far, so move the subresources up
	// and discard the identical per-version ones
	crd.Spec.Subresources = subres
	for i := range crd.Spec.Versions {
		crd.Spec.Versions[i].Subresources = nil
	}
}

// mergeIdenticalSchemata checks to see if schemata are identical across
// all versions, and if so, merges them into a top-level version.
//
// This assumes you're not using trivial versions.
func mergeIdenticalSchemata(crd *apiextv1beta1.CustomResourceDefinition) {
	schema := crd.Spec.Versions[0].Schema
	for _, ver := range crd.Spec.Versions {
		if ver.Schema == nil || !equality.Semantic.DeepEqual(schema, ver.Schema) {
			// either all nil, or not identical
			return
		}
	}

	// things are identical if we've gotten this far, so move the schemata up
	// to a single schema and discard the identical per-version ones
	crd.Spec.Validation = schema
	for i := range crd.Spec.Versions {
		crd.Spec.Versions[i].Schema = nil
	}
}

// mergeIdenticalPrinterColumns checks to see if schemata are identical across
// all versions, and if so, merges them into a top-level version.
//
// This assumes you're not using trivial versions.
func mergeIdenticalPrinterColumns(crd *apiextv1beta1.CustomResourceDefinition) {
	cols := crd.Spec.Versions[0].AdditionalPrinterColumns
	for _, ver := range crd.Spec.Versions {
		if len(ver.AdditionalPrinterColumns) == 0 || !equality.Semantic.DeepEqual(cols, ver.AdditionalPrinterColumns) {
			// either all nil, or not identical
			return
		}
	}

	// things are identical if we've gotten this far, so move the printer columns up
	// and discard the identical per-version ones
	crd.Spec.AdditionalPrinterColumns = cols
	for i := range crd.Spec.Versions {
		crd.Spec.Versions[i].AdditionalPrinterColumns = nil
	}
}

// MergeIdenticalVersionInfo makes sure that components of the Versions field that are identical
// across all versions get merged into the top-level fields in v1beta1.
//
// This is required by the Kubernetes API server validation.
//
// The reason is that a v1beta1 -> v1 -> v1beta1 conversion cycle would need to
// round-trip identically, v1 doesn't have top-level subresources, and without
// this restriction it would be ambiguous how a v1-with-identical-subresources
// converts into a v1beta1).
func MergeIdenticalVersionInfo(crd *apiextv1beta1.CustomResourceDefinition) {
	if len(crd.Spec.Versions) > 0 {
		mergeIdenticalSubresources(crd)
		mergeIdenticalSchemata(crd)
		mergeIdenticalPrinterColumns(crd)
	}
}
