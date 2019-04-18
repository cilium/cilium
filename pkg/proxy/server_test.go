// This code is copied from github.com/optiopay/kafka to provide the testing
// framework

// +build !privileged_tests

package proxy

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/lock"

	"github.com/optiopay/kafka/proto"
)

const (
	AnyRequest              = -1
	ProduceRequest          = 0
	FetchRequest            = 1
	OffsetRequest           = 2
	MetadataRequest         = 3
	OffsetCommitRequest     = 8
	OffsetFetchRequest      = 9
	ConsumerMetadataRequest = 10
)

type Serializable interface {
	Bytes(int16) ([]byte, error)
}

type RequestHandler func(request Serializable) (response Serializable)

type Server struct {
	Processed int

	mu       lock.RWMutex
	ln       net.Listener
	clients  map[int64]net.Conn
	handlers map[int16]RequestHandler
}

func NewServer() *Server {
	srv := &Server{
		clients:  make(map[int64]net.Conn),
		handlers: make(map[int16]RequestHandler),
	}
	srv.handlers[AnyRequest] = srv.defaultRequestHandler
	return srv
}

// Handle registers handler for given message kind. Handler registered with
// AnyRequest kind will be used only if there is no precise handler for the
// kind.
func (srv *Server) Handle(reqKind int16, handler RequestHandler) {
	srv.mu.Lock()
	srv.handlers[reqKind] = handler
	srv.mu.Unlock()
}

func (srv *Server) Address() string {
	return srv.ln.Addr().String()
}

func (srv *Server) HostPort() (string, int) {
	host, sport, err := net.SplitHostPort(srv.ln.Addr().String())
	if err != nil {
		panic(fmt.Sprintf("cannot split server address: %s", err))
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		panic(fmt.Sprintf("port '%s' is not a number: %s", sport, err))
	}
	if host == "" {
		host = "localhost"
	}
	return host, port
}

func (srv *Server) Start() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.ln != nil {
		panic("server already started")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:")
	if err != nil {
		panic(fmt.Sprintf("cannot start server: %s", err))
	}
	srv.ln = ln

	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleClient(client)
		}
	}()
}

func (srv *Server) Close() {
	srv.mu.Lock()
	_ = srv.ln.Close()
	for _, cli := range srv.clients {
		_ = cli.Close()
	}
	srv.clients = make(map[int64]net.Conn)
	srv.mu.Unlock()
}

func (srv *Server) handleClient(c net.Conn) {
	clientID := time.Now().UnixNano()
	srv.mu.Lock()
	srv.clients[clientID] = c
	srv.mu.Unlock()

	defer func() {
		srv.mu.Lock()
		delete(srv.clients, clientID)
		srv.mu.Unlock()
	}()

	for {
		kind, b, err := proto.ReadReq(c)
		if err != nil {
			return
		}
		srv.mu.RLock()
		fn, ok := srv.handlers[kind]
		if !ok {
			fn, ok = srv.handlers[AnyRequest]
		}
		srv.mu.RUnlock()

		if !ok {
			panic(fmt.Sprintf("no handler for %d", kind))
		}

		var request Serializable

		switch kind {
		case FetchRequest:
			request, err = proto.ReadFetchReq(bytes.NewBuffer(b))
		case ProduceRequest:
			request, err = proto.ReadProduceReq(bytes.NewBuffer(b))
		case OffsetRequest:
			request, err = proto.ReadOffsetReq(bytes.NewBuffer(b))
		case MetadataRequest:
			request, err = proto.ReadMetadataReq(bytes.NewBuffer(b))
		case ConsumerMetadataRequest:
			request, err = proto.ReadConsumerMetadataReq(bytes.NewBuffer(b))
		case OffsetCommitRequest:
			request, err = proto.ReadOffsetCommitReq(bytes.NewBuffer(b))
		case OffsetFetchRequest:
			request, err = proto.ReadOffsetFetchReq(bytes.NewBuffer(b))
		}

		if err != nil {
			panic(fmt.Sprintf("could not read message %d: %s", kind, err))
		}

		response := fn(request)
		if response != nil {
			b, err := response.Bytes(proto.KafkaV0)
			if err != nil {
				panic(fmt.Sprintf("cannot serialize %T: %s", response, err))
			}
			if _, err := c.Write(b); err != nil {
				panic(fmt.Sprintf("cannot wirte to client: %s", err))
			}
		}
	}
}

func (srv *Server) defaultRequestHandler(request Serializable) Serializable {
	srv.mu.RLock()
	defer srv.mu.RUnlock()

	srv.Processed++

	switch req := request.(type) {
	case *proto.FetchReq:
		resp := &proto.FetchResp{
			CorrelationID: req.CorrelationID,
			Topics:        make([]proto.FetchRespTopic, len(req.Topics)),
		}
		for ti, topic := range req.Topics {
			resp.Topics[ti] = proto.FetchRespTopic{
				Name:       topic.Name,
				Partitions: make([]proto.FetchRespPartition, len(topic.Partitions)),
			}
			for pi, part := range topic.Partitions {
				resp.Topics[ti].Partitions[pi] = proto.FetchRespPartition{
					ID:        part.ID,
					Err:       proto.ErrUnknownTopicOrPartition,
					TipOffset: -1,
					Messages:  []*proto.Message{},
				}
			}
		}
		return resp
	case *proto.ProduceReq:
		resp := &proto.ProduceResp{
			CorrelationID: req.CorrelationID,
		}
		resp.Topics = make([]proto.ProduceRespTopic, len(req.Topics))
		for ti, topic := range req.Topics {
			resp.Topics[ti] = proto.ProduceRespTopic{
				Name:       topic.Name,
				Partitions: make([]proto.ProduceRespPartition, len(topic.Partitions)),
			}
			for pi, part := range topic.Partitions {
				resp.Topics[ti].Partitions[pi] = proto.ProduceRespPartition{
					ID:     part.ID,
					Err:    proto.ErrUnknownTopicOrPartition,
					Offset: -1,
				}
			}
		}
		return resp
	case *proto.OffsetReq:
		topics := make([]proto.OffsetRespTopic, len(req.Topics))
		for ti := range req.Topics {
			var topic = &topics[ti]
			topic.Name = req.Topics[ti].Name
			topic.Partitions = make([]proto.OffsetRespPartition, len(req.Topics[ti].Partitions))
			for pi := range topic.Partitions {
				var part = &topic.Partitions[pi]
				part.ID = req.Topics[ti].Partitions[pi].ID
				part.Err = proto.ErrUnknownTopicOrPartition
			}
		}

		return &proto.OffsetResp{
			CorrelationID: req.CorrelationID,
			Topics:        topics,
		}
	case *proto.MetadataReq:
		host, sport, err := net.SplitHostPort(srv.ln.Addr().String())
		if err != nil {
			panic(fmt.Sprintf("cannot split server address: %s", err))
		}
		port, err := strconv.Atoi(sport)
		if err != nil {
			panic(fmt.Sprintf("port '%s' is not a number: %s", sport, err))
		}
		if host == "" {
			host = "localhost"
		}
		return &proto.MetadataResp{
			CorrelationID: req.CorrelationID,
			Brokers: []proto.MetadataRespBroker{
				{NodeID: 1, Host: host, Port: int32(port)},
			},
			Topics: []proto.MetadataRespTopic{},
		}
	case *proto.ConsumerMetadataReq:
		panic("not implemented")
	case *proto.OffsetCommitReq:
		panic("not implemented")
	case *proto.OffsetFetchReq:
		panic("not implemented")
	default:
		panic(fmt.Sprintf("unknown message type: %T", req))
	}
}
