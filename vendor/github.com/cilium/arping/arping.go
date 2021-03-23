// Package arping is a native go library to ping a host per arp datagram, or query a host mac address
//
// The currently supported platforms are: Linux and BSD.
//
//
// The library requires raw socket access. So it must run as root, or with appropriate capabilities under linux:
// `sudo setcap cap_net_raw+ep <BIN>`.
//
//
// Examples:
//
//   ping a host:
//   ------------
//     package main
//     import ("fmt"; "github.com/j-keck/arping"; "net")
//
//     func main(){
//       dstIP := net.ParseIP("192.168.1.1")
//       if hwAddr, duration, err := arping.Ping(dstIP); err != nil {
//         fmt.Println(err)
//       } else {
//         fmt.Printf("%s (%s) %d usec\n", dstIP, hwAddr, duration/1000)
//       }
//     }
//
//
//   resolve mac address:
//   --------------------
//     package main
//     import ("fmt"; "github.com/j-keck/arping"; "net")
//
//     func main(){
//       dstIP := net.ParseIP("192.168.1.1")
//       if hwAddr, _, err := arping.Ping(dstIP); err != nil {
//         fmt.Println(err)
//       } else {
//         fmt.Printf("%s is at %s\n", dstIP, hwAddr)
//       }
//     }
//
//
//   check if host is online:
//   ------------------------
//     package main
//     import ("fmt"; "github.com/j-keck/arping"; "net")
//
//     func main(){
//       dstIP := net.ParseIP("192.168.1.1")
//       _, _, err := arping.Ping(dstIP)
//       if err == arping.ErrTimeout {
//         fmt.Println("offline")
//       }else if err != nil {
//         fmt.Println(err.Error())
//       }else{
//         fmt.Println("online")
//       }
//     }
//
package arping

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/vishvananda/netlink"
)

var (
	// ErrTimeout error
	ErrTimeout = errors.New("timeout")
	ErrSize    = errors.New("truncated")

	verboseLog = log.New(ioutil.Discard, "", 0)
	timeout    = 1 * time.Second
	retries    = 3
)

type PingResult struct {
	mac      net.HardwareAddr
	duration time.Duration
	err      error
}

// PingOverIface sends an arp ping over interface 'iface' to 'dstIP' from 'srcIP'
func PingOverIface(dstIP net.IP, iface netlink.Link, srcIP net.IP) (hwAddr net.HardwareAddr, duration time.Duration, err error) {
	if err := validateIP(dstIP); err != nil {
		return nil, 0, err
	}

	srcMac := iface.Attrs().HardwareAddr
	broadcastMac := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	request := newArpRequest(srcMac, srcIP, broadcastMac, dstIP)

	req, err := initialize(iface)
	if err != nil {
		return nil, 0, err
	}
	defer req.deinitialize()

	for i := 0; i < retries; i++ {
		hwAddr, duration, err = ping(req, request, dstIP, iface, srcIP)
		if !errors.Is(err, ErrTimeout) {
			return
		}
	}

	return
}

func ping(req *requester, request arpDatagram, dstIP net.IP, iface netlink.Link, srcIP net.IP) (net.HardwareAddr, time.Duration, error) {
	pingResultChan := make(chan PingResult)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	go func() {
		// send arp request
		verboseLog.Printf("arping '%s' over interface: '%d' with address: '%s'\n", dstIP, iface.Attrs().Index, srcIP)
		sendTime, err := req.send(request)
		if err != nil {
			select {
			case pingResultChan <- PingResult{nil, 0, err}:
			case <-ctx.Done():
			}
			return
		}
		for {
			// receive arp response
			response, receiveTime, err := req.receive(timeout)

			if err != nil {
				select {
				case pingResultChan <- PingResult{nil, 0, err}:
				case <-ctx.Done():
				}
				return
			}

			if response.IsResponseOf(request) {
				duration := receiveTime.Sub(sendTime)
				verboseLog.Printf("process received arp: srcIP: '%s', srcMac: '%s'\n",
					response.SenderIP(), response.SenderMac())
				select {
				case pingResultChan <- PingResult{response.SenderMac(), duration, err}:
				case <-ctx.Done():
				}
				return
			}

			verboseLog.Printf("ignore received arp: srcIP: '%s', srcMac: '%s'\n",
				response.SenderIP(), response.SenderMac())
		}
	}()

	select {
	case pingResult := <-pingResultChan:
		return pingResult.mac, pingResult.duration, pingResult.err
	case <-ctx.Done():
		return nil, 0, ErrTimeout
	}
}

// EnableVerboseLog enables verbose logging on stdout
func EnableVerboseLog() {
	verboseLog = log.New(os.Stdout, "", 0)
}

// SetTimeout sets ping timeout
func SetTimeout(t time.Duration) {
	timeout = t
}

func validateIP(ip net.IP) error {
	// ip must be a valid V4 address
	if len(ip.To4()) != net.IPv4len {
		return fmt.Errorf("not a valid v4 Address: %s", ip)
	}
	return nil
}
