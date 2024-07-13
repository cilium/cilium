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
	"errors"
	"fmt"
)

// Common errors
var (
	ErrResolverUndefined     = errors.New("resolver undefined")
	ErrFromResolverUndefined = errors.New("from target resolver undefined")
	ErrToResolverUndefined   = errors.New("to target resolver undefined")
	ErrFromTargetUndefined   = errors.New("from target undefined")
	ErrToTargetUndefined     = errors.New("from target undefined")
)

// Path validation related errors
var (
	ErrDirtyPath               = errors.New("dirty path")
	ErrPathNotSlashSeparated   = errors.New("path not slash separated")
	ErrAbsolutePathDisallowed  = errors.New("absolute path disallowed")
	ErrPathTraversalDisallowed = errors.New("path traversal disallowed")
)

// ErrStopProcessing is used to stop processing an oras operation.
// This error only makes sense in sequential pulling operation.
var ErrStopProcessing = fmt.Errorf("stop processing")
