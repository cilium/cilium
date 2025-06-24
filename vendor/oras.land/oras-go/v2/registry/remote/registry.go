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

// Package remote provides a client to the remote registry.
// Reference: https://github.com/distribution/distribution
package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/internal/errutil"
)

// RepositoryOptions is an alias of Repository to avoid name conflicts.
// It also hides all methods associated with Repository.
type RepositoryOptions Repository

// Registry is an HTTP client to a remote registry.
type Registry struct {
	// RepositoryOptions contains common options for Registry and Repository.
	// It is also used as a template for derived repositories.
	RepositoryOptions

	// RepositoryListPageSize specifies the page size when invoking the catalog
	// API.
	// If zero, the page size is determined by the remote registry.
	// Reference: https://distribution.github.io/distribution/spec/api/#catalog
	RepositoryListPageSize int
}

// NewRegistry creates a client to the remote registry with the specified domain
// name.
// Example: localhost:5000
func NewRegistry(name string) (*Registry, error) {
	ref := registry.Reference{
		Registry: name,
	}
	if err := ref.ValidateRegistry(); err != nil {
		return nil, err
	}
	return &Registry{
		RepositoryOptions: RepositoryOptions{
			Reference: ref,
		},
	}, nil
}

// client returns an HTTP client used to access the remote registry.
// A default HTTP client is return if the client is not configured.
func (r *Registry) client() Client {
	if r.Client == nil {
		return auth.DefaultClient
	}
	return r.Client
}

// do sends an HTTP request and returns an HTTP response using the HTTP client
// returned by r.client().
func (r *Registry) do(req *http.Request) (*http.Response, error) {
	if r.HandleWarning == nil {
		return r.client().Do(req)
	}

	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	handleWarningHeaders(resp.Header.Values(headerWarning), r.HandleWarning)
	return resp, nil
}

// Ping checks whether or not the registry implement Docker Registry API V2 or
// OCI Distribution Specification.
// Ping can be used to check authentication when an auth client is configured.
//
// References:
//   - https://distribution.github.io/distribution/spec/api/#base
//   - https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#api
func (r *Registry) Ping(ctx context.Context) error {
	url := buildRegistryBaseURL(r.PlainHTTP, r.Reference)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := r.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return errdef.ErrNotFound
	default:
		return errutil.ParseErrorResponse(resp)
	}
}

// Repositories lists the name of repositories available in the registry.
// See also `RepositoryListPageSize`.
//
// If `last` is NOT empty, the entries in the response start after the
// repo specified by `last`. Otherwise, the response starts from the top
// of the Repositories list.
//
// Reference: https://distribution.github.io/distribution/spec/api/#catalog
func (r *Registry) Repositories(ctx context.Context, last string, fn func(repos []string) error) error {
	ctx = auth.AppendScopesForHost(ctx, r.Reference.Host(), auth.ScopeRegistryCatalog)
	url := buildRegistryCatalogURL(r.PlainHTTP, r.Reference)
	var err error
	for err == nil {
		url, err = r.repositories(ctx, last, fn, url)
		// clear `last` for subsequent pages
		last = ""
	}
	if err != errNoLink {
		return err
	}
	return nil
}

// repositories returns a single page of repository list with the next link.
func (r *Registry) repositories(ctx context.Context, last string, fn func(repos []string) error, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if r.RepositoryListPageSize > 0 || last != "" {
		q := req.URL.Query()
		if r.RepositoryListPageSize > 0 {
			q.Set("n", strconv.Itoa(r.RepositoryListPageSize))
		}
		if last != "" {
			q.Set("last", last)
		}
		req.URL.RawQuery = q.Encode()
	}
	resp, err := r.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errutil.ParseErrorResponse(resp)
	}
	var page struct {
		Repositories []string `json:"repositories"`
	}
	lr := limitReader(resp.Body, r.MaxMetadataBytes)
	if err := json.NewDecoder(lr).Decode(&page); err != nil {
		return "", fmt.Errorf("%s %q: failed to decode response: %w", resp.Request.Method, resp.Request.URL, err)
	}
	if err := fn(page.Repositories); err != nil {
		return "", err
	}

	return parseLink(resp)
}

// Repository returns a repository reference by the given name.
func (r *Registry) Repository(ctx context.Context, name string) (registry.Repository, error) {
	ref := registry.Reference{
		Registry:   r.Reference.Registry,
		Repository: name,
	}
	return newRepositoryWithOptions(ref, &r.RepositoryOptions)
}
