// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sha1

import (
	"crypto/sha1"
	"encoding"
	"encoding/hex"
	"fmt"
	"hash"
)

// ResumableHash is the intefrace for a hash that can be stored and copied.
//
// Unlike hash implementations in the standard library, it does not implement
// the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler interfaces;
// however, it does provide a method for creating a copy of the underlying
// hash. This allows the hash to be stored, duplicated, and resumed at a later
// time. For convenience, it also provides a standard method for converting
// the hash into a string.
type ResumableHash interface {
	hash.Hash
	fmt.Stringer
	Copy() (ResumableHash, error)
}

// digest is a wrapper for the standard sha1 library which implements
// ResumableHash.
type digest struct {
	hash.Hash
}

// New returns a new ResumableHash computing the SHA1 checksum.
func New() ResumableHash {
	return &digest{
		sha1.New(),
	}
}

// Copy duplicates the hash and returns the copy.
func (d *digest) Copy() (ResumableHash, error) {
	newHash := hash.Hash(sha1.New())
	state, err := d.Hash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err := newHash.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return nil, err
	}
	return &digest{
		newHash,
	}, nil
}

// String returns a string representation of the underlying hash.
func (d *digest) String() string {
	return hex.EncodeToString(d.Sum(nil))
}
