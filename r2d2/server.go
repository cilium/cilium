package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"strings"
)

func main() {
	var addr string
	flag.StringVar(&addr, "listen-address", "localhost:3333", "listen address")
	flag.Parse()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Error listening:", err.Error())
	}
	defer l.Close()

	log.Println("Listening on " + addr)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("Error accepting: ", err.Error())
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	reply := []byte("ERROR\r\n")
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err != nil {
		writeResponse(conn, buf, reply)
		return
	}

	data := string(buf)
	msgLen := strings.Index(data, "\r\n")
	if msgLen < 0 {
		writeResponse(conn, buf, reply)
		return
	}

	msgStr := data[:msgLen]
	msgLen += 2

	fields := strings.Split(msgStr, " ")
	if len(fields) < 1 {
		writeResponse(conn, buf, reply)
		return
	}

	cmd := fields[0]
	var filename string
	switch cmd {
	case "READ":
		if len(fields) != 2 {
			writeResponse(conn, buf, reply)
			return
		}
		filename = fields[1]
		log.Printf("READ file: %s\n", filename)
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			writeResponse(conn, buf, reply)
			return
		}
		reply = []byte("OK")
		reply = append(reply, content...)
		reply = append(reply, []byte("\r\n")...)
		writeResponse(conn, buf, reply)
		return
	case "WRITE":
		if len(fields) != 2 {
			writeResponse(conn, buf, reply)
			return
		}
		filename = fields[1]
		log.Printf("WRITE file: %s\n", filename)
		writeResponse(conn, buf, []byte("OK\r\n"))
		return
	case "HALT":
		if len(fields) != 1 {
			writeResponse(conn, buf, reply)
			return
		}
		writeResponse(conn, buf, []byte("OK\r\n"))
		return
	case "RESET":
		if len(fields) != 1 {
			writeResponse(conn, buf, reply)
			return
		}
		writeResponse(conn, buf, []byte("OK\r\n"))
		return
	default:
		writeResponse(conn, buf, reply)
		return
	}
}

func writeResponse(conn net.Conn, request []byte, reply []byte) {
	log.Printf("request: '%s'", request)
	conn.Write(reply)
	conn.Close()
}
