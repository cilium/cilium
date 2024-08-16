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

package content

import (
	"context"
	"errors"
	"strings"

	ctrcontent "github.com/containerd/containerd/content"
	"github.com/containerd/containerd/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Decompress store to decompress content and extract from tar, if needed, wrapping
// another store. By default, a FileStore will simply take each artifact and write it to
// a file, as a MemoryStore will do into memory. If the artifact is gzipped or tarred,
// you might want to store the actual object inside tar or gzip. Wrap your Store
// with Decompress, and it will check the media-type and, if relevant,
// gunzip and/or untar.
//
// For example:
//
//        fileStore := NewFileStore(rootPath)
//        Decompress := store.NewDecompress(fileStore, WithBlocksize(blocksize))
//
// The above example works if there is no tar, i.e. each artifact is just a single file, perhaps gzipped,
// or if there is only one file in each tar archive. In other words, when each content.Writer has only one target output stream.
// However, if you have multiple files in each tar archive, each archive of which is an artifact layer, then
// you need a way to select how to handle each file in the tar archive. In other words, when each content.Writer has more than one
// target output stream. In that case, use the following example:
//
//        multiStore := NewMultiStore(rootPath) // some store that can handle different filenames
//        Decompress := store.NewDecompress(multiStore, WithBlocksize(blocksize), WithMultiWriterIngester())
//
type Decompress struct {
	pusher              remotes.Pusher
	blocksize           int
	multiWriterIngester bool
}

func NewDecompress(pusher remotes.Pusher, opts ...WriterOpt) Decompress {
	// we have to reprocess the opts to find the blocksize
	var wOpts WriterOpts
	for _, opt := range opts {
		if err := opt(&wOpts); err != nil {
			// TODO: we probably should handle errors here
			continue
		}
	}

	return Decompress{pusher, wOpts.Blocksize, wOpts.MultiWriterIngester}
}

// Push get a content.Writer
func (d Decompress) Push(ctx context.Context, desc ocispec.Descriptor) (ctrcontent.Writer, error) {
	// the logic is straightforward:
	// - if there is a desc in the opts, and the mediatype is tar or tar+gzip, then pass the correct decompress writer
	// - else, pass the regular writer
	var (
		writer        ctrcontent.Writer
		err           error
		multiIngester MultiWriterPusher
		ok            bool
	)

	// check to see if we are supposed to use a MultiWriterIngester
	if d.multiWriterIngester {
		multiIngester, ok = d.pusher.(MultiWriterPusher)
		if !ok {
			return nil, errors.New("configured to use multiwriter ingester, but ingester does not implement multiwriter")
		}
	}

	// figure out if compression and/or archive exists
	// before we pass it down, we need to strip anything we are removing here
	// and possibly update the digest, since the store indexes things by digest
	hasGzip, hasTar, modifiedMediaType := checkCompression(desc.MediaType)
	desc.MediaType = modifiedMediaType
	// determine if we pass it blocksize, only if positive
	writerOpts := []WriterOpt{}
	if d.blocksize > 0 {
		writerOpts = append(writerOpts, WithBlocksize(d.blocksize))
	}

	writer, err = d.pusher.Push(ctx, desc)
	if err != nil {
		return nil, err
	}

	// do we need to wrap with an untar writer?
	if hasTar {
		// if not multiingester, get a regular writer
		if multiIngester == nil {
			writer = NewUntarWriter(writer, writerOpts...)
		} else {
			writers, err := multiIngester.Pushers(ctx, desc)
			if err != nil {
				return nil, err
			}
			writer = NewUntarWriterByName(writers, writerOpts...)
		}
	}
	if hasGzip {
		if writer == nil {
			writer, err = d.pusher.Push(ctx, desc)
			if err != nil {
				return nil, err
			}
		}
		writer = NewGunzipWriter(writer, writerOpts...)
	}
	return writer, nil
}

// checkCompression check if the mediatype uses gzip compression or tar.
// Returns if it has gzip and/or tar, as well as the base media type without
// those suffixes.
func checkCompression(mediaType string) (gzip, tar bool, mt string) {
	mt = mediaType
	gzipSuffix := "+gzip"
	gzipAltSuffix := ".gzip"
	tarSuffix := ".tar"
	switch {
	case strings.HasSuffix(mt, gzipSuffix):
		mt = mt[:len(mt)-len(gzipSuffix)]
		gzip = true
	case strings.HasSuffix(mt, gzipAltSuffix):
		mt = mt[:len(mt)-len(gzipAltSuffix)]
		gzip = true
	}

	if strings.HasSuffix(mt, tarSuffix) {
		mt = mt[:len(mt)-len(tarSuffix)]
		tar = true
	}
	return
}
