// Copyright 2024 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build darwin
// +build darwin

package layers

import (
	"github.com/gopacket/gopacket"
)

/*
#define DLT_USER2		149

#ifdef __APPLE__
#define DLT_PKTAP	DLT_USER2
#else
#define DLT_PKTAP	258
#endif
*/

func init() {
	LinkTypeMetadata[LinkTypeApplePKTAP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePktapV1), Name: "ApplePKTAP"}
}
