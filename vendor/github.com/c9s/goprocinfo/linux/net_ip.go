package linux

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	ipv4RegExp = regexp.MustCompile("^[0-9a-fA-F]{8}:[0-9a-fA-F]{4}$")  // Regex for NetIPv4Decoder
	ipv6RegExp = regexp.MustCompile("^[0-9a-fA-F]{32}:[0-9a-fA-F]{4}$") // Regex for NetIPv6Decoder
)

type NetIPDecoder func(string) (string, error) // Either NetIPv4Decoder or NetIPv6Decoder

type NetSocket struct {
	LocalAddress         string `json:"local_address"`
	RemoteAddress        string `json:"remote_address"`
	Status               uint8  `json:"st"`
	TxQueue              uint64 `json:"tx_queue"`
	RxQueue              uint64 `json:"rx_queue"`
	Uid                  uint32 `json:"uid"`
	Inode                uint64 `json:"inode"`
	SocketReferenceCount uint64 `json:"ref"`
}

func parseNetSocket(f []string, ip NetIPDecoder) (*NetSocket, error) {

	if len(f) < 11 {
		return nil, errors.New("Cannot parse net socket line: " + strings.Join(f, " "))
	}

	if strings.Index(f[4], ":") == -1 {
		return nil, errors.New("Cannot parse tx/rx queues: " + f[4])
	}

	q := strings.Split(f[4], ":")

	socket := &NetSocket{}

	var s uint64  // socket.Status
	var u uint64  // socket.Uid
	var err error // parse error

	if socket.LocalAddress, err = ip(f[1]); err != nil {
		return nil, err
	}

	if socket.RemoteAddress, err = ip(f[2]); err != nil {
		return nil, err
	}

	if s, err = strconv.ParseUint(f[3], 16, 8); err != nil {
		return nil, err
	}

	if socket.TxQueue, err = strconv.ParseUint(q[0], 16, 64); err != nil {
		return nil, err
	}

	if socket.RxQueue, err = strconv.ParseUint(q[1], 16, 64); err != nil {
		return nil, err
	}

	if u, err = strconv.ParseUint(f[7], 10, 32); err != nil {
		return nil, err
	}

	if socket.Inode, err = strconv.ParseUint(f[9], 10, 64); err != nil {
		return nil, err
	}

	if socket.SocketReferenceCount, err = strconv.ParseUint(f[10], 10, 64); err != nil {
		return nil, err
	}

	socket.Status = uint8(s)
	socket.Uid = uint32(u)

	return socket, nil
}

// NetIPv4Decoder decodes an IPv4 address with port from a given hex string
// NOTE: This function match NetIPDecoder type
func NetIPv4Decoder(s string) (string, error) {

	if !ipv4RegExp.MatchString(s) {
		return "", errors.New("Cannot decode ipv4 address: " + s)
	}

	i := strings.Split(s, ":")

	b := make([]byte, 4)

	for j := 0; j < 4; j++ {

		x := j * 2
		y := x + 2
		z := 3 - j

		// Extract 2 characters from hex string, 4 times.
		//
		// s: "0100007F" -> [
		//     h: "01", h: "00", h: "00", h: "7F",
		// ]
		h := i[0][x:y]

		// Reverse byte order
		n, _ := strconv.ParseUint(h, 16, 8)
		b[z] = byte(n)

	}

	h := net.IP(b).String()
	n, _ := strconv.ParseUint(i[1], 16, 64)
	p := strconv.FormatUint(n, 10)

	// ipv4:port
	v := h + ":" + p

	return v, nil
}

// NetIPv6Decoder decodes an IPv6 address with port from a given hex string
// NOTE: This function match NetIPDecoder type
func NetIPv6Decoder(s string) (string, error) {

	if !ipv6RegExp.MatchString(s) {
		return "", errors.New("Cannot decode ipv6 address: " + s)
	}

	i := strings.Split(s, ":")

	b := make([]byte, 16)

	for j := 0; j < 4; j++ {

		x := j * 8
		y := x + 8

		// Extract 8 characters from hex string, 4 times.
		//
		// s: "350E012A900F122E85EDEAADA64DAAD1" -> [
		//     h: "350E012A", h: "900F122E",
		//     h: "85EDEAAD", h: "A64DAAD1",
		// ]
		h := i[0][x:y]

		for k := 0; k < 4; k++ {

			// Reverse byte order
			// "350E012A" -> [ 0x2A, 0x01, 0x0E, 0x35 ]
			z := (j * 4) + k
			g := 8 - (k * 2)
			f := g - 2

			n, _ := strconv.ParseUint(h[f:g], 16, 8)
			b[z] = byte(n)

		}
	}

	h := net.IP(b).String()
	n, _ := strconv.ParseUint(i[1], 16, 64)
	p := strconv.FormatUint(n, 10)

	// ipv6:port
	v := h + ":" + p

	return v, nil
}
