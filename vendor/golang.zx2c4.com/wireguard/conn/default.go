//go:build !linux && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

package conn

func NewDefaultBind() Bind { return NewStdNetBind() }
