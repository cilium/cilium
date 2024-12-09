// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.23

package checker

// This type is a placeholder for go1.23's iter.Seq[*Action].
type actionSeq func(yield func(*Action) bool)
