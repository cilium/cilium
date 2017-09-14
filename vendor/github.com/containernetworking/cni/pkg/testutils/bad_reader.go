// Copyright 2016 CNI authors
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

package testutils

import "errors"

// BadReader is an io.Reader which always errors
type BadReader struct {
	Error error
}

func (r *BadReader) Read(buffer []byte) (int, error) {
	if r.Error != nil {
		return 0, r.Error
	}
	return 0, errors.New("banana")
}

func (r *BadReader) Close() error {
	return nil
}
