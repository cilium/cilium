package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
)

type NetworkStat struct {
	Iface        string `json:"iface"`
	RxBytes      uint64 `json:"rxbytes"`
	RxPackets    uint64 `json:"rxpackets"`
	RxErrs       uint64 `json:"rxerrs"`
	RxDrop       uint64 `json:"rxdrop"`
	RxFifo       uint64 `json:"rxfifo"`
	RxFrame      uint64 `json:"rxframe"`
	RxCompressed uint64 `json:"rxcompressed"`
	RxMulticast  uint64 `json:"rxmulticast"`
	TxBytes      uint64 `json:"txbytes"`
	TxPackets    uint64 `json:"txpackets"`
	TxErrs       uint64 `json:"txerrs"`
	TxDrop       uint64 `json:"txdrop"`
	TxFifo       uint64 `json:"txfifo"`
	TxColls      uint64 `json:"txcolls"`
	TxCarrier    uint64 `json:"txcarrier"`
	TxCompressed uint64 `json:"txcompressed"`
}

func ReadNetworkStat(path string) ([]NetworkStat, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")

	// lines[2:] remove /proc/net/dev header
	results := make([]NetworkStat, len(lines[2:])-1)

	for i, line := range lines[2:] {
		// patterns
		// <iface>: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
		// or
		// <iface>:0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 (without space after colon)
		colon := strings.Index(line, ":")

		if colon > 0 {
			metrics := line[colon+1:]
			fields := strings.Fields(metrics)

			results[i].Iface = strings.Replace(line[0:colon], " ", "", -1)
			results[i].RxBytes, _ = strconv.ParseUint(fields[0], 10, 64)
			results[i].RxPackets, _ = strconv.ParseUint(fields[1], 10, 64)
			results[i].RxErrs, _ = strconv.ParseUint(fields[2], 10, 64)
			results[i].RxDrop, _ = strconv.ParseUint(fields[3], 10, 64)
			results[i].RxFifo, _ = strconv.ParseUint(fields[4], 10, 64)
			results[i].RxFrame, _ = strconv.ParseUint(fields[5], 10, 64)
			results[i].RxCompressed, _ = strconv.ParseUint(fields[6], 10, 64)
			results[i].RxMulticast, _ = strconv.ParseUint(fields[7], 10, 64)
			results[i].TxBytes, _ = strconv.ParseUint(fields[8], 10, 64)
			results[i].TxPackets, _ = strconv.ParseUint(fields[9], 10, 64)
			results[i].TxErrs, _ = strconv.ParseUint(fields[10], 10, 64)
			results[i].TxDrop, _ = strconv.ParseUint(fields[11], 10, 64)
			results[i].TxFifo, _ = strconv.ParseUint(fields[12], 10, 64)
			results[i].TxColls, _ = strconv.ParseUint(fields[13], 10, 64)
			results[i].TxCarrier, _ = strconv.ParseUint(fields[14], 10, 64)
			results[i].TxCompressed, _ = strconv.ParseUint(fields[15], 10, 64)
		}
	}

	return results, nil
}
