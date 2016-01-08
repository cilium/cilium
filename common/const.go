package common

const (
	PluginPath = "/run/docker/plugins/"
	DriverSock = PluginPath + "cilium.sock"
	CiliumPath = "/var/run/cilium/"
	CiliumSock = CiliumPath + "cilium.sock"
)
