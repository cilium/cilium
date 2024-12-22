package mapcidr

import (
	"fmt"
	"net"
)

// Item represent a combination of ip:port
type Item struct {
	IP   string
	Port int
}

// String returns the item as ip:port
func (i Item) String() string {
	return net.JoinHostPort(i.IP, fmt.Sprintf("%d", i.Port))
}
