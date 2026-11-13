// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package crds embeds the Gateway API standard channel CRDs matching the
// version of sigs.k8s.io/gateway-api pinned in go.mod.
//
// The manifests are copied from the upstream module by
// contrib/scripts/gateway-api-crds-sync.sh (run as part of `make manifests`)
// and must not be edited manually.
package crds

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

const (
	// BundleVersionAnnotation is the annotation set by upstream on every
	// Gateway API CRD with the Gateway API release it belongs to.
	BundleVersionAnnotation = "gateway.networking.k8s.io/bundle-version"
	// ChannelAnnotation is the annotation set by upstream on every Gateway
	// API CRD with the release channel it belongs to.
	ChannelAnnotation = "gateway.networking.k8s.io/channel"

	ChannelStandard     = "standard"
	ChannelExperimental = "experimental"
)

//go:embed standard/*.yaml
var standardFS embed.FS

// Standard returns the embedded Gateway API standard channel CRDs, sorted by
// name.
func Standard() ([]*apiextensionsv1.CustomResourceDefinition, error) {
	return load(standardFS, "standard")
}

func load(fsys fs.FS, dir string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}

	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.UnmarshalStrict(b, crd); err != nil {
			return nil, fmt.Errorf("unable to unmarshal Gateway API CRD %s: %w", entry.Name(), err)
		}
		if crd.Kind != "CustomResourceDefinition" {
			return nil, fmt.Errorf("unexpected kind %q in %s", crd.Kind, entry.Name())
		}
		crds = append(crds, crd)
	}

	slices.SortFunc(crds, func(a, b *apiextensionsv1.CustomResourceDefinition) int {
		return strings.Compare(a.Name, b.Name)
	})
	return crds, nil
}
