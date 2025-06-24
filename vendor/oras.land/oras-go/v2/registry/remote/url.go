/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package remote

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/registry"
)

// buildScheme returns HTTP scheme used to access the remote registry.
func buildScheme(plainHTTP bool) string {
	if plainHTTP {
		return "http"
	}
	return "https"
}

// buildRegistryBaseURL builds the URL for accessing the base API.
// Format: <scheme>://<registry>/v2/
// Reference: https://distribution.github.io/distribution/spec/api/#base
func buildRegistryBaseURL(plainHTTP bool, ref registry.Reference) string {
	return fmt.Sprintf("%s://%s/v2/", buildScheme(plainHTTP), ref.Host())
}

// buildRegistryCatalogURL builds the URL for accessing the catalog API.
// Format: <scheme>://<registry>/v2/_catalog
// Reference: https://distribution.github.io/distribution/spec/api/#catalog
func buildRegistryCatalogURL(plainHTTP bool, ref registry.Reference) string {
	return fmt.Sprintf("%s://%s/v2/_catalog", buildScheme(plainHTTP), ref.Host())
}

// buildRepositoryBaseURL builds the base endpoint of the remote repository.
// Format: <scheme>://<registry>/v2/<repository>
func buildRepositoryBaseURL(plainHTTP bool, ref registry.Reference) string {
	return fmt.Sprintf("%s://%s/v2/%s", buildScheme(plainHTTP), ref.Host(), ref.Repository)
}

// buildRepositoryTagListURL builds the URL for accessing the tag list API.
// Format: <scheme>://<registry>/v2/<repository>/tags/list
// Reference: https://distribution.github.io/distribution/spec/api/#tags
func buildRepositoryTagListURL(plainHTTP bool, ref registry.Reference) string {
	return buildRepositoryBaseURL(plainHTTP, ref) + "/tags/list"
}

// buildRepositoryManifestURL builds the URL for accessing the manifest API.
// Format: <scheme>://<registry>/v2/<repository>/manifests/<digest_or_tag>
// Reference: https://distribution.github.io/distribution/spec/api/#manifest
func buildRepositoryManifestURL(plainHTTP bool, ref registry.Reference) string {
	return strings.Join([]string{
		buildRepositoryBaseURL(plainHTTP, ref),
		"manifests",
		ref.Reference,
	}, "/")
}

// buildRepositoryBlobURL builds the URL for accessing the blob API.
// Format: <scheme>://<registry>/v2/<repository>/blobs/<digest>
// Reference: https://distribution.github.io/distribution/spec/api/#blob
func buildRepositoryBlobURL(plainHTTP bool, ref registry.Reference) string {
	return strings.Join([]string{
		buildRepositoryBaseURL(plainHTTP, ref),
		"blobs",
		ref.Reference,
	}, "/")
}

// buildRepositoryBlobUploadURL builds the URL for blob uploading.
// Format: <scheme>://<registry>/v2/<repository>/blobs/uploads/
// Reference: https://distribution.github.io/distribution/spec/api/#initiate-blob-upload
func buildRepositoryBlobUploadURL(plainHTTP bool, ref registry.Reference) string {
	return buildRepositoryBaseURL(plainHTTP, ref) + "/blobs/uploads/"
}

// buildRepositoryBlobMountURLbuilds the URL for cross-repository mounting.
// Format: <scheme>://<registry>/v2/<repository>/blobs/uploads/?mount=<digest>&from=<other_repository>
// Reference: https://distribution.github.io/distribution/spec/api/#blob
func buildRepositoryBlobMountURL(plainHTTP bool, ref registry.Reference, d digest.Digest, fromRepo string) string {
	return fmt.Sprintf("%s?mount=%s&from=%s",
		buildRepositoryBlobUploadURL(plainHTTP, ref),
		d,
		fromRepo,
	)
}

// buildReferrersURL builds the URL for querying the Referrers API.
// Format: <scheme>://<registry>/v2/<repository>/referrers/<digest>?artifactType=<artifactType>
// Reference: https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-referrers
func buildReferrersURL(plainHTTP bool, ref registry.Reference, artifactType string) string {
	var query string
	if artifactType != "" {
		v := url.Values{}
		v.Set("artifactType", artifactType)
		query = "?" + v.Encode()
	}

	return fmt.Sprintf(
		"%s/referrers/%s%s",
		buildRepositoryBaseURL(plainHTTP, ref),
		ref.Reference,
		query,
	)
}
