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
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
)

// LimitedStorage represents a CAS with a push size limit.
type LimitedStorage struct {
	Storage         // underlying storage
	PushLimit int64 // max size for push
}

// Push pushes the content, matching the expected descriptor.
// The size of the content cannot exceed the push size limit.
func (ls *LimitedStorage) Push(ctx context.Context, expected ocispec.Descriptor, content io.Reader) error {
	if expected.Size > ls.PushLimit {
		return fmt.Errorf(
			"content size %v exceeds push size limit %v: %w",
			expected.Size,
			ls.PushLimit,
			errdef.ErrSizeExceedsLimit)
	}

	return ls.Storage.Push(ctx, expected, io.LimitReader(content, expected.Size))
}

// LimitStorage returns a storage with a push size limit.
func LimitStorage(s Storage, n int64) *LimitedStorage {
	return &LimitedStorage{s, n}
}
