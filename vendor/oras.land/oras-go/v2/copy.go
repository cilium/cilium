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
	"errors"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/internal/cas"
	"oras.land/oras-go/v2/internal/descriptor"
	"oras.land/oras-go/v2/internal/platform"
	"oras.land/oras-go/v2/internal/registryutil"
	"oras.land/oras-go/v2/internal/status"
	"oras.land/oras-go/v2/internal/syncutil"
	"oras.land/oras-go/v2/registry"
)

// defaultConcurrency is the default value of CopyGraphOptions.Concurrency.
const defaultConcurrency int = 3 // This value is consistent with dockerd and containerd.

// SkipNode signals to stop copying a node. When returned from PreCopy the blob must exist in the target.
// This can be used to signal that a blob has been made available in the target repository by "Mount()" or some other technique.
var SkipNode = errors.New("skip node")

// DefaultCopyOptions provides the default CopyOptions.
var DefaultCopyOptions CopyOptions = CopyOptions{
	CopyGraphOptions: DefaultCopyGraphOptions,
}

// CopyOptions contains parameters for [oras.Copy].
type CopyOptions struct {
	CopyGraphOptions
	// MapRoot maps the resolved root node to a desired root node for copy.
	// When MapRoot is provided, the descriptor resolved from the source
	// reference will be passed to MapRoot, and the mapped descriptor will be
	// used as the root node for copy.
	MapRoot func(ctx context.Context, src content.ReadOnlyStorage, root ocispec.Descriptor) (ocispec.Descriptor, error)
}

// WithTargetPlatform configures opts.MapRoot to select the manifest whose
// platform matches the given platform. When MapRoot is provided, the platform
// selection will be applied on the mapped root node.
//   - If the given platform is nil, no platform selection will be applied.
//   - If the root node is a manifest, it will remain the same if platform
//     matches, otherwise ErrNotFound will be returned.
//   - If the root node is a manifest list, it will be mapped to the first
//     matching manifest if exists, otherwise ErrNotFound will be returned.
//   - Otherwise ErrUnsupported will be returned.
func (opts *CopyOptions) WithTargetPlatform(p *ocispec.Platform) {
	if p == nil {
		return
	}
	mapRoot := opts.MapRoot
	opts.MapRoot = func(ctx context.Context, src content.ReadOnlyStorage, root ocispec.Descriptor) (desc ocispec.Descriptor, err error) {
		if mapRoot != nil {
			if root, err = mapRoot(ctx, src, root); err != nil {
				return ocispec.Descriptor{}, err
			}
		}
		return platform.SelectManifest(ctx, src, root, p)
	}
}

// defaultCopyMaxMetadataBytes is the default value of
// CopyGraphOptions.MaxMetadataBytes.
const defaultCopyMaxMetadataBytes int64 = 4 * 1024 * 1024 // 4 MiB

// DefaultCopyGraphOptions provides the default CopyGraphOptions.
var DefaultCopyGraphOptions CopyGraphOptions

// CopyGraphOptions contains parameters for [oras.CopyGraph].
type CopyGraphOptions struct {
	// Concurrency limits the maximum number of concurrent copy tasks.
	// If less than or equal to 0, a default (currently 3) is used.
	Concurrency int
	// MaxMetadataBytes limits the maximum size of the metadata that can be
	// cached in the memory.
	// If less than or equal to 0, a default (currently 4 MiB) is used.
	MaxMetadataBytes int64
	// PreCopy handles the current descriptor before it is copied. PreCopy can
	// return a SkipNode to signal that desc should be skipped when it already
	// exists in the target.
	PreCopy func(ctx context.Context, desc ocispec.Descriptor) error
	// PostCopy handles the current descriptor after it is copied.
	PostCopy func(ctx context.Context, desc ocispec.Descriptor) error
	// OnCopySkipped will be called when the sub-DAG rooted by the current node
	// is skipped.
	OnCopySkipped func(ctx context.Context, desc ocispec.Descriptor) error
	// MountFrom returns the candidate repositories that desc may be mounted from.
	// The OCI references will be tried in turn.  If mounting fails on all of them,
	// then it falls back to a copy.
	MountFrom func(ctx context.Context, desc ocispec.Descriptor) ([]string, error)
	// OnMounted will be invoked when desc is mounted.
	OnMounted func(ctx context.Context, desc ocispec.Descriptor) error
	// FindSuccessors finds the successors of the current node.
	// fetcher provides cached access to the source storage, and is suitable
	// for fetching non-leaf nodes like manifests. Since anything fetched from
	// fetcher will be cached in the memory, it is recommended to use original
	// source storage to fetch large blobs.
	// If FindSuccessors is nil, content.Successors will be used.
	FindSuccessors func(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) ([]ocispec.Descriptor, error)
}

// Copy copies a rooted directed acyclic graph (DAG) with the tagged root node
// in the source Target to the destination Target.
// The destination reference will be the same as the source reference if the
// destination reference is left blank.
//
// Returns the descriptor of the root node on successful copy.
func Copy(ctx context.Context, src ReadOnlyTarget, srcRef string, dst Target, dstRef string, opts CopyOptions) (ocispec.Descriptor, error) {
	if src == nil {
		return ocispec.Descriptor{}, errors.New("nil source target")
	}
	if dst == nil {
		return ocispec.Descriptor{}, errors.New("nil destination target")
	}
	if dstRef == "" {
		dstRef = srcRef
	}

	// use caching proxy on non-leaf nodes
	if opts.MaxMetadataBytes <= 0 {
		opts.MaxMetadataBytes = defaultCopyMaxMetadataBytes
	}
	proxy := cas.NewProxyWithLimit(src, cas.NewMemory(), opts.MaxMetadataBytes)
	root, err := resolveRoot(ctx, src, srcRef, proxy)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to resolve %s: %w", srcRef, err)
	}

	if opts.MapRoot != nil {
		proxy.StopCaching = true
		root, err = opts.MapRoot(ctx, proxy, root)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		proxy.StopCaching = false
	}

	if err := prepareCopy(ctx, dst, dstRef, proxy, root, &opts); err != nil {
		return ocispec.Descriptor{}, err
	}

	if err := copyGraph(ctx, src, dst, root, proxy, nil, nil, opts.CopyGraphOptions); err != nil {
		return ocispec.Descriptor{}, err
	}

	return root, nil
}

// CopyGraph copies a rooted directed acyclic graph (DAG) from the source CAS to
// the destination CAS.
func CopyGraph(ctx context.Context, src content.ReadOnlyStorage, dst content.Storage, root ocispec.Descriptor, opts CopyGraphOptions) error {
	return copyGraph(ctx, src, dst, root, nil, nil, nil, opts)
}

// copyGraph copies a rooted directed acyclic graph (DAG) from the source CAS to
// the destination CAS with specified caching, concurrency limiter and tracker.
func copyGraph(ctx context.Context, src content.ReadOnlyStorage, dst content.Storage, root ocispec.Descriptor,
	proxy *cas.Proxy, limiter *semaphore.Weighted, tracker *status.Tracker, opts CopyGraphOptions) error {
	if proxy == nil {
		// use caching proxy on non-leaf nodes
		if opts.MaxMetadataBytes <= 0 {
			opts.MaxMetadataBytes = defaultCopyMaxMetadataBytes
		}
		proxy = cas.NewProxyWithLimit(src, cas.NewMemory(), opts.MaxMetadataBytes)
	}
	if limiter == nil {
		// if Concurrency is not set or invalid, use the default concurrency
		if opts.Concurrency <= 0 {
			opts.Concurrency = defaultConcurrency
		}
		limiter = semaphore.NewWeighted(int64(opts.Concurrency))
	}
	if tracker == nil {
		// track content status
		tracker = status.NewTracker()
	}
	// if FindSuccessors is not provided, use the default one
	if opts.FindSuccessors == nil {
		opts.FindSuccessors = content.Successors
	}

	// traverse the graph
	var fn syncutil.GoFunc[ocispec.Descriptor]
	fn = func(ctx context.Context, region *syncutil.LimitedRegion, desc ocispec.Descriptor) (err error) {
		// skip the descriptor if other go routine is working on it
		done, committed := tracker.TryCommit(desc)
		if !committed {
			return nil
		}
		defer func() {
			if err == nil {
				// mark the content as done on success
				close(done)
			}
		}()

		// skip if a rooted sub-DAG exists
		exists, err := dst.Exists(ctx, desc)
		if err != nil {
			return err
		}
		if exists {
			if opts.OnCopySkipped != nil {
				if err := opts.OnCopySkipped(ctx, desc); err != nil {
					return err
				}
			}
			return nil
		}

		// find successors while non-leaf nodes will be fetched and cached
		successors, err := opts.FindSuccessors(ctx, proxy, desc)
		if err != nil {
			return err
		}
		successors = removeForeignLayers(successors)

		if len(successors) != 0 {
			// for non-leaf nodes, process successors and wait for them to complete
			region.End()
			if err := syncutil.Go(ctx, limiter, fn, successors...); err != nil {
				return err
			}
			for _, node := range successors {
				done, committed := tracker.TryCommit(node)
				if committed {
					return fmt.Errorf("%s: %s: successor not committed", desc.Digest, node.Digest)
				}
				select {
				case <-done:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if err := region.Start(); err != nil {
				return err
			}
		}

		exists, err = proxy.Cache.Exists(ctx, desc)
		if err != nil {
			return err
		}
		if exists {
			return copyNode(ctx, proxy.Cache, dst, desc, opts)
		}
		return mountOrCopyNode(ctx, src, dst, desc, opts)
	}

	return syncutil.Go(ctx, limiter, fn, root)
}

// mountOrCopyNode tries to mount the node, if not falls back to copying.
func mountOrCopyNode(ctx context.Context, src content.ReadOnlyStorage, dst content.Storage, desc ocispec.Descriptor, opts CopyGraphOptions) error {
	// Need MountFrom and it must be a blob
	if opts.MountFrom == nil || descriptor.IsManifest(desc) {
		return copyNode(ctx, src, dst, desc, opts)
	}

	mounter, ok := dst.(registry.Mounter)
	if !ok {
		// mounting is not supported by the destination
		return copyNode(ctx, src, dst, desc, opts)
	}

	sourceRepositories, err := opts.MountFrom(ctx, desc)
	if err != nil {
		// Technically this error is not fatal, we can still attempt to copy the node
		// But for consistency with the other callbacks we bail out.
		return err
	}

	if len(sourceRepositories) == 0 {
		return copyNode(ctx, src, dst, desc, opts)
	}

	skipSource := errors.New("skip source")
	for i, sourceRepository := range sourceRepositories {
		// try mounting this source repository
		var mountFailed bool
		getContent := func() (io.ReadCloser, error) {
			// the invocation of getContent indicates that mounting has failed
			mountFailed = true

			if i < len(sourceRepositories)-1 {
				// If this is not the last one, skip this source and try next one
				// We want to return an error that we will test for from mounter.Mount()
				return nil, skipSource
			}
			// this is the last iteration so we need to actually get the content and do the copy
			// but first call the PreCopy function
			if opts.PreCopy != nil {
				if err := opts.PreCopy(ctx, desc); err != nil {
					return nil, err
				}
			}
			return src.Fetch(ctx, desc)
		}

		// Mount or copy
		if err := mounter.Mount(ctx, desc, sourceRepository, getContent); err != nil && !errors.Is(err, skipSource) {
			return err
		}

		if !mountFailed {
			// mounted, success
			if opts.OnMounted != nil {
				if err := opts.OnMounted(ctx, desc); err != nil {
					return err
				}
			}
			return nil
		}
	}

	// we copied it
	if opts.PostCopy != nil {
		if err := opts.PostCopy(ctx, desc); err != nil {
			return err
		}
	}

	return nil
}

// doCopyNode copies a single content from the source CAS to the destination CAS.
func doCopyNode(ctx context.Context, src content.ReadOnlyStorage, dst content.Storage, desc ocispec.Descriptor) error {
	rc, err := src.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer rc.Close()
	err = dst.Push(ctx, desc, rc)
	if err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return err
	}
	return nil
}

// copyNode copies a single content from the source CAS to the destination CAS,
// and apply the given options.
func copyNode(ctx context.Context, src content.ReadOnlyStorage, dst content.Storage, desc ocispec.Descriptor, opts CopyGraphOptions) error {
	if opts.PreCopy != nil {
		if err := opts.PreCopy(ctx, desc); err != nil {
			if err == SkipNode {
				return nil
			}
			return err
		}
	}

	if err := doCopyNode(ctx, src, dst, desc); err != nil {
		return err
	}

	if opts.PostCopy != nil {
		return opts.PostCopy(ctx, desc)
	}
	return nil
}

// copyCachedNodeWithReference copies a single content with a reference from the
// source cache to the destination ReferencePusher.
func copyCachedNodeWithReference(ctx context.Context, src *cas.Proxy, dst registry.ReferencePusher, desc ocispec.Descriptor, dstRef string) error {
	rc, err := src.FetchCached(ctx, desc)
	if err != nil {
		return err
	}
	defer rc.Close()

	err = dst.PushReference(ctx, desc, rc, dstRef)
	if err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return err
	}
	return nil
}

// resolveRoot resolves the source reference to the root node.
func resolveRoot(ctx context.Context, src ReadOnlyTarget, srcRef string, proxy *cas.Proxy) (ocispec.Descriptor, error) {
	refFetcher, ok := src.(registry.ReferenceFetcher)
	if !ok {
		return src.Resolve(ctx, srcRef)
	}

	// optimize performance for ReferenceFetcher targets
	refProxy := &registryutil.Proxy{
		ReferenceFetcher: refFetcher,
		Proxy:            proxy,
	}
	root, rc, err := refProxy.FetchReference(ctx, srcRef)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer rc.Close()
	// cache root if it is a non-leaf node
	fetcher := content.FetcherFunc(func(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
		if content.Equal(target, root) {
			return rc, nil
		}
		return nil, errors.New("fetching only root node expected")
	})
	if _, err = content.Successors(ctx, fetcher, root); err != nil {
		return ocispec.Descriptor{}, err
	}

	// TODO: optimize special case where root is a leaf node (i.e. a blob)
	//       and dst is a ReferencePusher.
	return root, nil
}

// prepareCopy prepares the hooks for copy.
func prepareCopy(ctx context.Context, dst Target, dstRef string, proxy *cas.Proxy, root ocispec.Descriptor, opts *CopyOptions) error {
	if refPusher, ok := dst.(registry.ReferencePusher); ok {
		// optimize performance for ReferencePusher targets
		preCopy := opts.PreCopy
		opts.PreCopy = func(ctx context.Context, desc ocispec.Descriptor) error {
			if preCopy != nil {
				if err := preCopy(ctx, desc); err != nil {
					return err
				}
			}
			if !content.Equal(desc, root) {
				// for non-root node, do nothing
				return nil
			}

			// for root node, prepare optimized copy
			if err := copyCachedNodeWithReference(ctx, proxy, refPusher, desc, dstRef); err != nil {
				return err
			}
			if opts.PostCopy != nil {
				if err := opts.PostCopy(ctx, desc); err != nil {
					return err
				}
			}
			// skip the regular copy workflow
			return SkipNode
		}
	} else {
		postCopy := opts.PostCopy
		opts.PostCopy = func(ctx context.Context, desc ocispec.Descriptor) error {
			if content.Equal(desc, root) {
				// for root node, tag it after copying it
				if err := dst.Tag(ctx, root, dstRef); err != nil {
					return err
				}
			}
			if postCopy != nil {
				return postCopy(ctx, desc)
			}
			return nil
		}
	}

	onCopySkipped := opts.OnCopySkipped
	opts.OnCopySkipped = func(ctx context.Context, desc ocispec.Descriptor) error {
		if !content.Equal(desc, root) {
			if onCopySkipped != nil {
				return onCopySkipped(ctx, desc)
			}
			return nil
		}

		// enforce tagging when the skipped node is root
		if refPusher, ok := dst.(registry.ReferencePusher); ok {
			// NOTE: refPusher tags the node by copying it with the reference,
			// so onCopySkipped shouldn't be invoked in this case
			return copyCachedNodeWithReference(ctx, proxy, refPusher, desc, dstRef)
		}

		// invoke onCopySkipped before tagging
		if onCopySkipped != nil {
			if err := onCopySkipped(ctx, desc); err != nil {
				return err
			}
		}
		return dst.Tag(ctx, root, dstRef)
	}

	return nil
}

// removeForeignLayers in-place removes all foreign layers in the given slice.
func removeForeignLayers(descs []ocispec.Descriptor) []ocispec.Descriptor {
	var j int
	for i, desc := range descs {
		if !descriptor.IsForeignLayer(desc) {
			if i != j {
				descs[j] = desc
			}
			j++
		}
	}
	return descs[:j]
}
