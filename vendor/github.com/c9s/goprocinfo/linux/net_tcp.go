package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
)

type NetTCPSockets struct {
	Sockets []NetTCPSocket `json:"sockets"`
}

type NetTCPSocket struct {
	NetSocket
	RetransmitTimeout       uint64 `json:"retransmit_timeout"`
	PredictedTick           uint64 `json:"predicted_tick"`
	AckQuick                uint8  `json:"ack_quick"`
	AckPingpong             bool   `json:"ack_pingpong"`
	SendingCongestionWindow uint64 `json:"sending_congestion_window"`
	SlowStartSizeThreshold  int64  `json:"slow_start_size_threshold"`
}

func ReadNetTCPSockets(path string, ip NetIPDecoder) (*NetTCPSockets, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(b), "\n")

	tcp := &NetTCPSockets{}

	for i := 1; i < len(lines); i++ {

		line := lines[i]

		f := strings.Fields(line)

		if len(f) < 17 {
			continue
		}

		s, err := parseNetSocket(f, ip)

		if err != nil {
			return nil, err
		}

		var n int64
		e := &NetTCPSocket{
			NetSocket: *s,
		}

		if e.RetransmitTimeout, err = strconv.ParseUint(f[12], 10, 64); err != nil {
			return nil, err
		}

		if e.PredictedTick, err = strconv.ParseUint(f[13], 10, 64); err != nil {
			return nil, err
		}

		if n, err = strconv.ParseInt(f[14], 10, 8); err != nil {
			return nil, err
		}
		e.AckQuick = uint8(n >> 1)
		e.AckPingpong = ((n & 1) == 1)

		if e.SendingCongestionWindow, err = strconv.ParseUint(f[15], 10, 64); err != nil {
			return nil, err
		}

		if e.SlowStartSizeThreshold, err = strconv.ParseInt(f[16], 10, 32); err != nil {
			return nil, err
		}

		tcp.Sockets = append(tcp.Sockets, *e)
	}

	return tcp, nil
}
