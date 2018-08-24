package main

import (
	"net"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

type AccessLogClient struct {
	path string
	conn *net.UnixConn
}

var accessLogClient *AccessLogClient

func (cl *AccessLogClient) connect() bool {
	if cl.conn != nil || len(cl.path) == 0 {
		return true
	}
	log.Debugf("init(): Connecting to Cilium Access Log socket: %s", cl.path)
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: cl.path, Net: "unixpacket"})
	if err != nil {
		log.Errorf("Access Log: Connect failed: %v", err)
		return false
	}
	cl.conn = conn
	return true
}

func (cl *AccessLogClient) Log(pblog *cilium.LogEntry) {
	if cl.connect() {
		// Encode
		logmsg, err := proto.Marshal(pblog)
		if err != nil {
			log.Errorf("marshaling error: %v", err)
		}

		// Write
		bytes, err := cl.conn.Write(logmsg)
		if err != nil {
			log.Errorf("Access Log: Write failed: %v", err)
			cl.conn.Close()
			cl.conn = nil
		} else {
			log.Debugf("Access Log: Wrote message (%d bytes): %s", bytes, pblog.String())
		}
	}
}

func startAccessLogClient(accessLogPath string) bool {
	accessLogClient = &AccessLogClient{path: accessLogPath}

	return accessLogClient.connect()
}
