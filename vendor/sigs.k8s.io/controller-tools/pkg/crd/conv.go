package crd

import (
	"fmt"

	apiextinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
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
}

// AsVersion converts a CRD from the canonical internal form (currently v1) to some external form.
func AsVersion(original apiext.CustomResourceDefinition, gv schema.GroupVersion) (runtime.Object, error) {
	// TODO: Do we need to keep maintaining this conversion function
	//       post 1.22 when only CRDv1 is served by the apiserver?
	if gv == apiextv1beta1.SchemeGroupVersion {
		return nil, fmt.Errorf("apiVersion %q is not supported", gv.String())
	}
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
