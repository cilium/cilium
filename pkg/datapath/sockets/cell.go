package sockets

import "github.com/cilium/hive/cell"

// Cell provides a socket inet probe used for probing for nl
// socket functionality. Results are memoized for subsequent
// calls by other consumers.
var Cell = cell.Module(
	"sockets-inet-probe",
	"Sockets Inet Probe",
	cell.Provide(newSocketInetProbe),
)
