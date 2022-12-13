package types

type AuthKey struct {
	LocalIdentity  uint32 `align:"local_sec_label"`
	RemoteIdentity uint32 `align:"remote_sec_label"`
	RemoteNodeID   uint16 `align:"remote_node_id"`
	AuthType       uint8  `align:"auth_type"`
	Pad            uint8  `align:"pad"`
}

type AuthInfo struct {
	Expiration uint64 `align:"expiration"`
}
