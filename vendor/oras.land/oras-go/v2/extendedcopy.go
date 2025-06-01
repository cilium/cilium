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

package oras

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/internal/cas"
	"oras.land/oras-go/v2/internal/container/set"
	"oras.land/oras-go/v2/internal/copyutil"
	"oras.land/oras-go/v2/internal/descriptor"
	"oras.land/oras-go/v2/internal/docker"
	"oras.land/oras-go/v2/internal/spec"
	"oras.land/oras-go/v2/internal/status"
	"oras.land/oras-go/v2/internal/syncutil"
	"oras.land/oras-go/v2/registry"
)

// DefaultExtendedCopyOptions provides the default ExtendedCopyOptions.
var DefaultExtendedCopyOptions ExtendedCopyOptions = ExtendedCopyOptions{
	ExtendedCopyGraphOptions: DefaultExtendedCopyGraphOptions,
}

// ExtendedCopyOptions contains parameters for [oras.ExtendedCopy].
type ExtendedCopyOptions struct {
	ExtendedCopyGraphOptions
}

// DefaultExtendedCopyGraphOptions provides the default ExtendedCopyGraphOptions.
var DefaultExtendedCopyGraphOptions ExtendedCopyGraphOptions = ExtendedCopyGraphOptions{
	CopyGraphOptions: DefaultCopyGraphOptions,
}

// ExtendedCopyGraphOptions contains parameters for [oras.ExtendedCopyGraph].
type ExtendedCopyGraphOptions struct {
	CopyGraphOptions
	// Depth limits the maximum depth of the directed acyclic graph (DAG) that
	// will be extended-copied.
	// If Depth is no specified, or the specified value is less than or
	// equal to 0, the depth limit will be considered as infinity.
	Depth int
	// FindPredecessors finds the predecessors of the current node.
	// If FindPredecessors is nil, src.Predecessors will be adapted and used.
	FindPredecessors func(ctx context.Context, src content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error)
}

// ExtendedCopy copies the directed acyclic graph (DAG) that are reachable from
// the given tagged node from the source GraphTarget to the destination Target.
// The destination reference will be the same as the source reference if the
// destination reference is left blank.
//
// Returns the descriptor of the tagged node on successful copy.
func ExtendedCopy(ctx context.Context, src ReadOnlyGraphTarget, srcRef string, dst Target, dstRef string, opts ExtendedCopyOptions) (ocispec.Descriptor, error) {
	if src == nil {
		return ocispec.Descriptor{}, errors.New("nil source graph target")
	}
	if dst == nil {
		return ocispec.Descriptor{}, errors.New("nil destination target")
	}
	if dstRef == "" {
		dstRef = srcRef
	}

	node, err := src.Resolve(ctx, srcRef)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	if err := ExtendedCopyGraph(ctx, src, dst, node, opts.ExtendedCopyGraphOptions); err != nil {
		return ocispec.Descriptor{}, err
	}

	if err := dst.Tag(ctx, node, dstRef); err != nil {
		return ocispec.Descriptor{}, err
	}

	return node, nil
}

// ExtendedCopyGraph copies the directed acyclic graph (DAG) that are reachable
// from the given node from the source GraphStorage to the destination Storage.
func ExtendedCopyGraph(ctx context.Context, src content.ReadOnlyGraphStorage, dst content.Storage, node ocispec.Descriptor, opts ExtendedCopyGraphOptions) error {
	roots, err := findRoots(ctx, src, node, opts)
	if err != nil {
		return err
	}

	// if Concurrency is not set or invalid, use the default concurrency
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	limiter := semaphore.NewWeighted(int64(opts.Concurrency))
	// use caching proxy on non-leaf nodes
	if opts.MaxMetadataBytes <= 0 {
		opts.MaxMetadataBytes = defaultCopyMaxMetadataBytes
	}
	proxy := cas.NewProxyWithLimit(src, cas.NewMemory(), opts.MaxMetadataBytes)
	// track content status
	tracker := status.NewTracker()

	// copy the sub-DAGs rooted by the root nodes
	return syncutil.Go(ctx, limiter, func(ctx context.Context, region *syncutil.LimitedRegion, root ocispec.Descriptor) error {
		// As a root can be a predecessor of other roots, release the limit here
		// for dispatching, to avoid dead locks where predecessor roots are
		// handled first and are waiting for its successors to complete.
		region.End()
		if err := copyGraph(ctx, src, dst, root, proxy, limiter, tracker, opts.CopyGraphOptions); err != nil {
			return err
		}
		return region.Start()
	}, roots...)
}

// findRoots finds the root nodes reachable from the given node through a
// depth-first search.
func findRoots(ctx context.Context, storage content.ReadOnlyGraphStorage, node ocispec.Descriptor, opts ExtendedCopyGraphOptions) ([]ocispec.Descriptor, error) {
	visited := set.New[descriptor.Descriptor]()
	rootMap := make(map[descriptor.Descriptor]ocispec.Descriptor)
	addRoot := func(key descriptor.Descriptor, val ocispec.Descriptor) {
		if _, exists := rootMap[key]; !exists {
			rootMap[key] = val
		}
	}

	// if FindPredecessors is not provided, use the default one
	if opts.FindPredecessors == nil {
		opts.FindPredecessors = func(ctx context.Context, src content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			return src.Predecessors(ctx, desc)
		}
	}

	var stack copyutil.Stack
	// push the initial node to the stack, set the depth to 0
	stack.Push(copyutil.NodeInfo{Node: node, Depth: 0})
	for {
		current, ok := stack.Pop()
		if !ok {
			// empty stack
			break
		}
		currentNode := current.Node
		currentKey := descriptor.FromOCI(currentNode)

		if visited.Contains(currentKey) {
			// skip the current node if it has been visited
			continue
		}
		visited.Add(currentKey)

		// stop finding predecessors if the target depth is reached
		if opts.Depth > 0 && current.Depth == opts.Depth {
			addRoot(currentKey, currentNode)
			continue
		}

		predecessors, err := opts.FindPredecessors(ctx, storage, currentNode)
		if err != nil {
			return nil, err
		}

		// The current node has no predecessor node,
		// which means it is a root node of a sub-DAG.
		if len(predecessors) == 0 {
			addRoot(currentKey, currentNode)
			continue
		}

		// The current node has predecessor nodes, which means it is NOT a root node.
		// Push the predecessor nodes to the stack and keep finding from there.
		for _, predecessor := range predecessors {
			predecessorKey := descriptor.FromOCI(predecessor)
			if !visited.Contains(predecessorKey) {
				// push the predecessor node with increased depth
				stack.Push(copyutil.NodeInfo{Node: predecessor, Depth: current.Depth + 1})
			}
		}
	}

	roots := make([]ocispec.Descriptor, 0, len(rootMap))
	for _, root := range rootMap {
		roots = append(roots, root)
	}
	return roots, nil
}

// FilterAnnotation configures opts.FindPredecessors to filter the predecessors
// whose annotation matches a given regex pattern.
//
// A predecessor is kept if key is in its annotations and the annotation value
// matches regex.
// If regex is nil, predecessors whose annotations contain key will be kept,
// no matter of the annotation value.
//
// For performance consideration, when using both FilterArtifactType and
// FilterAnnotation, it's recommended to call FilterArtifactType first.
func (opts *ExtendedCopyGraphOptions) FilterAnnotation(key string, regex *regexp.Regexp) {
	keep := func(desc ocispec.Descriptor) bool {
		value, ok := desc.Annotations[key]
		return ok && (regex == nil || regex.MatchString(value))
	}

	fp := opts.FindPredecessors
	opts.FindPredecessors = func(ctx context.Context, src content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		var predecessors []ocispec.Descriptor
		var err error
		if fp == nil {
			if rf, ok := src.(registry.ReferrerLister); ok {
				// if src is a ReferrerLister, use Referrers() for possible memory saving
				if err := rf.Referrers(ctx, desc, "", func(referrers []ocispec.Descriptor) error {
					// for each page of the results, filter the referrers
					for _, r := range referrers {
						if keep(r) {
							predecessors = append(predecessors, r)
						}
					}
					return nil
				}); err != nil {
					return nil, err
				}
				return predecessors, nil
			}
			predecessors, err = src.Predecessors(ctx, desc)
		} else {
			predecessors, err = fp(ctx, src, desc)
		}
		if err != nil {
			return nil, err
		}

		// Predecessor descriptors that are not from Referrers API are not
		// guaranteed to include the annotations of the corresponding manifests.
		var kept []ocispec.Descriptor
		for _, p := range predecessors {
			if p.Annotations == nil {
				// If the annotations are not present in the descriptors,
				// fetch it from the manifest content.
				switch p.MediaType {
				case docker.MediaTypeManifest, ocispec.MediaTypeImageManifest,
					docker.MediaTypeManifestList, ocispec.MediaTypeImageIndex,
					spec.MediaTypeArtifactManifest:
					annotations, err := fetchAnnotations(ctx, src, p)
					if err != nil {
						return nil, err
					}
					p.Annotations = annotations
				}
			}
			if keep(p) {
				kept = append(kept, p)
			}
		}
		return kept, nil
	}
}

// fetchAnnotations fetches the annotations of the manifest described by desc.
func fetchAnnotations(ctx context.Context, src content.ReadOnlyGraphStorage, desc ocispec.Descriptor) (map[string]string, error) {
	rc, err := src.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var manifest struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
		return nil, err
	}
	if manifest.Annotations == nil {
		// to differentiate with nil
		return make(map[string]string), nil
	}
	return manifest.Annotations, nil
}

// FilterArtifactType configures opts.FindPredecessors to filter the
// predecessors whose artifact type matches a given regex pattern.
//
// A predecessor is kept if its artifact type matches regex.
// If regex is nil, all predecessors will be kept.
//
// For performance consideration, when using both FilterArtifactType and
// FilterAnnotation, it's recommended to call FilterArtifactType first.
func (opts *ExtendedCopyGraphOptions) FilterArtifactType(regex *regexp.Regexp) {
	if regex == nil {
		return
	}
	keep := func(desc ocispec.Descriptor) bool {
		return regex.MatchString(desc.ArtifactType)
	}

	fp := opts.FindPredecessors
	opts.FindPredecessors = func(ctx context.Context, src content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		var predecessors []ocispec.Descriptor
		var err error
		if fp == nil {
			if rf, ok := src.(registry.ReferrerLister); ok {
				// if src is a ReferrerLister, use Referrers() for possible memory saving
				if err := rf.Referrers(ctx, desc, "", func(referrers []ocispec.Descriptor) error {
					// for each page of the results, filter the referrers
					for _, r := range referrers {
						if keep(r) {
							predecessors = append(predecessors, r)
						}
					}
					return nil
				}); err != nil {
					return nil, err
				}
				return predecessors, nil
			}
			predecessors, err = src.Predecessors(ctx, desc)
		} else {
			predecessors, err = fp(ctx, src, desc)
		}
		if err != nil {
			return nil, err
		}

		// predecessor descriptors that are not from Referrers API are not
		// guaranteed to include the artifact type of the corresponding
		// manifests.
		var kept []ocispec.Descriptor
		for _, p := range predecessors {
			if p.ArtifactType == "" {
				// if the artifact type is not present in the descriptors,
				// fetch it from the manifest content.
				switch p.MediaType {
				case spec.MediaTypeArtifactManifest, ocispec.MediaTypeImageManifest:
					artifactType, err := fetchArtifactType(ctx, src, p)
					if err != nil {
						return nil, err
					}
					p.ArtifactType = artifactType
				}
			}
			if keep(p) {
				kept = append(kept, p)
			}
		}
		return kept, nil
	}
}

// fetchArtifactType fetches the artifact type of the manifest described by desc.
func fetchArtifactType(ctx context.Context, src content.ReadOnlyGraphStorage, desc ocispec.Descriptor) (string, error) {
	rc, err := src.Fetch(ctx, desc)
	if err != nil {
		return "", err
	}
	defer rc.Close()

	switch desc.MediaType {
	case spec.MediaTypeArtifactManifest:
		var manifest spec.Artifact
		if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
			return "", err
		}
		return manifest.ArtifactType, nil
	case ocispec.MediaTypeImageManifest:
		var manifest ocispec.Manifest
		if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
			return "", err
		}
		return manifest.Config.MediaType, nil
	default:
		return "", nil
	}
}
