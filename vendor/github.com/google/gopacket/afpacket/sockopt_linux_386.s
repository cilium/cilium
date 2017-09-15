// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

TEXT	·socketcall(SB),4,$0-36
	JMP	syscall·socketcall(SB)