/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2005 Microsoft
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package winpipe

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go pipe.go file.go
