package datapathplugins

// CollectionKey returns a key that identifies the unique combination
// of BPF collection + attachment point that can be used as a primary
// key in statedb.
func (ac *AttachmentContext) CollectionKey() string {
	switch ac.Context.(type) {
	case *AttachmentContext_Host_:
		return "device/" + ac.GetHost().GetIface().GetName() + "/tc"
	case *AttachmentContext_Lxc:
		return "device/" +
			ac.GetLxc().GetPodInfo().GetNamespace() + "/" +
			ac.GetLxc().GetPodInfo().GetName() + "/" +
			ac.GetLxc().GetIface().GetName() + "/tc"
	case *AttachmentContext_Overlay_:
		return "device/" + ac.GetOverlay().GetIface().GetName() + "/tc"
	case *AttachmentContext_Wireguard_:
		return "device/" + ac.GetWireguard().GetIface().GetName() + "/tc"
	case *AttachmentContext_Xdp:
		return "device/" + ac.GetXdp().GetIface().GetName() + "/xdp"
	case *AttachmentContext_Socket_:
		return "cgroup/root"
	}

	return "unknown"
}

// GetDevice returns the device name for this attachment context if
// present.
func (ac *AttachmentContext) GetDevice() string {
	switch ac.Context.(type) {
	case *AttachmentContext_Host_:
		return ac.GetHost().GetIface().GetName()
	case *AttachmentContext_Lxc:
		return ac.GetLxc().GetIface().GetName()
	case *AttachmentContext_Overlay_:
		return ac.GetOverlay().GetIface().GetName()
	case *AttachmentContext_Wireguard_:
		return ac.GetWireguard().GetIface().GetName()
	case *AttachmentContext_Xdp:
		return ac.GetXdp().GetIface().GetName()
	}

	return ""
}
