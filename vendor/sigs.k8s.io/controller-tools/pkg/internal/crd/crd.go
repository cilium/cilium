package crd

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

func GroupVersionForPackage(pkgMarkers markers.MarkerValues, pkg *loader.Package) schema.GroupVersion {
	if nameVal := pkgMarkers.Get("groupName"); nameVal != nil {
		versionVal := pkg.Name // a reasonable guess
		if versionMarker := pkgMarkers.Get("versionName"); versionMarker != nil {
			versionVal = versionMarker.(string)
		}

		return schema.GroupVersion{
			Version: versionVal,
			Group:   nameVal.(string),
		}
	}

	return schema.GroupVersion{}
}
