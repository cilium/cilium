package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
)

type NetUDPSockets struct {
	Sockets []NetUDPSocket `json:"sockets"`
}

type NetUDPSocket struct {
	NetSocket
	Drops uint64 `json:"drops"`
}

func ReadNetUDPSockets(path string, ip NetIPDecoder) (*NetUDPSockets, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(b), "\n")

	udp := &NetUDPSockets{}

	for i := 1; i < len(lines); i++ {

		line := lines[i]

		f := strings.Fields(line)

		if len(f) < 13 {
			continue
		}

		s, err := parseNetSocket(f, ip)

		if err != nil {
			return nil, err
		}

		e := &NetUDPSocket{
			NetSocket: *s,
			Drops:     0,
		}

		if e.Drops, err = strconv.ParseUint(f[12], 10, 64); err != nil {
			return nil, err
		}

		udp.Sockets = append(udp.Sockets, *e)
	}

	return udp, nil
}
