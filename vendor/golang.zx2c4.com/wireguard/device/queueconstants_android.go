/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import "golang.zx2c4.com/wireguard/conn"

/* Reduce memory consumption for Android */

const (
	QueueStagedSize            = conn.IdealBatchSize
	QueueOutboundSize          = 1024
	QueueInboundSize           = 1024
	QueueHandshakeSize         = 1024
	MaxSegmentSize             = 2200
	PreallocatedBuffersPerPool = 4096
)
