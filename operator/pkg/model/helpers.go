package model

import "github.com/google/go-cmp/cmp"

func AddSource(sourceList []FullyQualifiedResource, source FullyQualifiedResource) []FullyQualifiedResource {

	var found bool
	for _, s := range sourceList {
		if cmp.Equal(s, source) {
			found = true
		}
	}

	if !found {
		sourceList = append(sourceList, source)
	}

	return sourceList
}
