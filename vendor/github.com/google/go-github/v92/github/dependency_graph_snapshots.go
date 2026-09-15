// Copyright 2023 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// DependencyGraphSnapshotResolvedDependency represents a resolved dependency in a dependency graph snapshot.
//
// GitHub API docs: https://docs.github.com/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
type DependencyGraphSnapshotResolvedDependency struct {
	PackageURL *string `json:"package_url,omitempty"`
	// User-defined metadata to store domain-specific information limited to 8 keys with scalar values.
	// This metadata overrides auto-detected values from the package URL and GitHub's database.
	// Common fields include:
	//   - "licenses": license information (e.g., "MIT", "Apache-2.0")
	//   - "name": package name
	//   - "version": package version
	//   - "manager": package manager (e.g., "npm", "pip", "maven")
	//   - "description": package description
	Metadata map[string]any `json:"metadata,omitempty"`
	// Represents whether the dependency is requested directly by the manifest or is a dependency of another dependency.
	// Can have the following values:
	//   - "direct": indicates that the dependency is requested directly by the manifest.
	//   - "indirect": indicates that the dependency is a dependency of another dependency.
	Relationship *string `json:"relationship,omitempty"`
	// Represents whether the dependency is required for the primary build artifact or is only used for development.
	// Can have the following values:
	//   - "runtime": indicates that the dependency is required for the primary build artifact.
	//   - "development": indicates that the dependency is only used for development.
	Scope        *string  `json:"scope,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// DependencyGraphSnapshotJob represents the job that created the snapshot.
//
// GitHub API docs: https://docs.github.com/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
type DependencyGraphSnapshotJob struct {
	Correlator string  `json:"correlator"`
	ID         string  `json:"id"`
	HTMLURL    *string `json:"html_url,omitempty"`
}

// DependencyGraphSnapshotDetector represents a description of the detector used.
//
// GitHub API docs: https://docs.github.com/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
type DependencyGraphSnapshotDetector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

// DependencyGraphSnapshotManifestFile represents the file declaring the repository's dependencies.
//
// GitHub API docs: https://docs.github.com/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
type DependencyGraphSnapshotManifestFile struct {
	SourceLocation *string `json:"source_location,omitempty"`
}

// DependencyGraphSnapshotManifest represents a collection of related dependencies declared in a file or representing a logical group of dependencies.
//
// GitHub API docs: https://docs.github.com/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
type DependencyGraphSnapshotManifest struct {
	Name     string                                                `json:"name"`
	File     *DependencyGraphSnapshotManifestFile                  `json:"file,omitempty"`
	Metadata map[string]any                                        `json:"metadata,omitempty"`
	Resolved map[string]*DependencyGraphSnapshotResolvedDependency `json:"resolved,omitempty"`
}

// CreateDependencyGraphSnapshotRequest represents a request to create a snapshot of a repository's dependencies.
//
// GitHub API docs: https://docs.github.com/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
//
//meta:schema request POST /repos/{owner}/{repo}/dependency-graph/snapshots
type CreateDependencyGraphSnapshotRequest struct {
	Version   int                                         `json:"version"`
	SHA       string                                      `json:"sha"`
	Ref       string                                      `json:"ref"`
	Job       DependencyGraphSnapshotJob                  `json:"job"`
	Detector  DependencyGraphSnapshotDetector             `json:"detector"`
	Scanned   Timestamp                                   `json:"scanned"`
	Metadata  map[string]any                              `json:"metadata,omitempty"`
	Manifests map[string]*DependencyGraphSnapshotManifest `json:"manifests,omitempty"`
}

// DependencyGraphSnapshotCreationData represents the dependency snapshot's creation result.
//
// GitHub API docs: https://docs.github.com/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
type DependencyGraphSnapshotCreationData struct {
	ID        int64      `json:"id"`
	CreatedAt *Timestamp `json:"created_at,omitempty"`
	Message   *string    `json:"message,omitempty"`
	// Represents the snapshot creation result.
	// Can have the following values:
	//   - "SUCCESS": indicates that the snapshot was successfully created and the repository's dependencies were updated.
	//   - "ACCEPTED": indicates that the snapshot was successfully created, but the repository's dependencies were not updated.
	//   - "INVALID": indicates that the snapshot was malformed.
	Result *string `json:"result,omitempty"`
}

// CreateSnapshot creates a new snapshot of a repository's dependencies.
//
// GitHub API docs: https://docs.github.com/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository
//
//meta:operation POST /repos/{owner}/{repo}/dependency-graph/snapshots
func (s *DependencyGraphService) CreateSnapshot(ctx context.Context, owner, repo string, body CreateDependencyGraphSnapshotRequest) (*DependencyGraphSnapshotCreationData, *Response, error) {
	url := fmt.Sprintf("repos/%v/%v/dependency-graph/snapshots", owner, repo)

	req, err := s.client.NewRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, nil, err
	}

	var snapshotCreationData *DependencyGraphSnapshotCreationData
	resp, err := s.client.Do(req, &snapshotCreationData)
	if err != nil {
		return nil, resp, err
	}

	return snapshotCreationData, resp, nil
}
