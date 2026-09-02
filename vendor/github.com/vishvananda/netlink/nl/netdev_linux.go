package nl

// Constants for the "netdev" generic netlink family, mirroring
// include/uapi/linux/netdev.h. Only the subset required for queue
// management (queue-get, queue-create) and queue leasing is defined here.

const (
	NETDEV_FAMILY_NAME    = "netdev"
	NETDEV_FAMILY_VERSION = 1
)

// netdev_queue_type
const (
	NETDEV_QUEUE_TYPE_RX = iota
	NETDEV_QUEUE_TYPE_TX
)

// Commands (enum netdev_cmd). Numbering starts at 1 to match the UAPI, where
// NETDEV_CMD_DEV_GET = 1.
const (
	NETDEV_CMD_DEV_GET = iota + 1
	NETDEV_CMD_DEV_ADD_NTF
	NETDEV_CMD_DEV_DEL_NTF
	NETDEV_CMD_DEV_CHANGE_NTF
	NETDEV_CMD_PAGE_POOL_GET
	NETDEV_CMD_PAGE_POOL_ADD_NTF
	NETDEV_CMD_PAGE_POOL_DEL_NTF
	NETDEV_CMD_PAGE_POOL_CHANGE_NTF
	NETDEV_CMD_PAGE_POOL_STATS_GET
	NETDEV_CMD_QUEUE_GET
	NETDEV_CMD_NAPI_GET
	NETDEV_CMD_QSTATS_GET
	NETDEV_CMD_BIND_RX
	NETDEV_CMD_NAPI_SET
	NETDEV_CMD_BIND_TX
	NETDEV_CMD_QUEUE_CREATE
)

// Queue attribute set (enum starting at NETDEV_A_QUEUE_ID = 1).
const (
	NETDEV_A_QUEUE_ID = iota + 1
	NETDEV_A_QUEUE_IFINDEX
	NETDEV_A_QUEUE_TYPE
	NETDEV_A_QUEUE_NAPI_ID
	NETDEV_A_QUEUE_DMABUF
	NETDEV_A_QUEUE_IO_URING
	NETDEV_A_QUEUE_XSK
	NETDEV_A_QUEUE_LEASE
)

// Lease nested attribute set (enum starting at NETDEV_A_LEASE_IFINDEX = 1).
const (
	NETDEV_A_LEASE_IFINDEX = iota + 1
	NETDEV_A_LEASE_QUEUE
	NETDEV_A_LEASE_NETNS_ID
)
