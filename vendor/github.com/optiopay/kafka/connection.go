package kafka

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/optiopay/kafka/proto"
)

// ErrClosed is returned as result of any request made using closed connection.
var ErrClosed = errors.New("closed")

// Low level abstraction over connection to Kafka.
type connection struct {
	rw     net.Conn
	stop   chan struct{}
	nextID chan int32
	logger Logger

	mu          sync.Mutex
	respc       map[int32]chan []byte
	stopErr     error
	readTimeout time.Duration
	apiVersions map[int16]proto.SupportedVersion
}

func newTLSConnection(address string, ca, cert, key []byte, timeout, readTimeout time.Duration) (*connection, error) {
	var fetchVersions = true
	for {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(ca)
		if !ok {
			return nil, fmt.Errorf("Cannot parse root certificate")
		}

		certificate, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse key/cert for TLS: %s", err)
		}

		conf := &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      roots,
		}

		dialer := net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}
		conn, err := tls.DialWithDialer(&dialer, "tcp", address, conf)
		if err != nil {
			return nil, err
		}
		c := &connection{
			stop:        make(chan struct{}),
			nextID:      make(chan int32),
			rw:          conn,
			respc:       make(map[int32]chan []byte),
			logger:      &nullLogger{},
			readTimeout: readTimeout,
			apiVersions: make(map[int16]proto.SupportedVersion),
		}
		go c.nextIDLoop()
		go c.readRespLoop()
		if fetchVersions {
			if c.cacheApiVersions() != nil {
				fetchVersions = false
				//required for errorchk
				_ = c.Close()
			}
		}

		return c, nil
	}

}

// newConnection returns new, initialized connection or error
func newTCPConnection(address string, timeout, readTimeout time.Duration) (*connection, error) {
	var fetchVersions = true
	for {
		dialer := net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}
		conn, err := dialer.Dial("tcp", address)
		if err != nil {
			return nil, err
		}
		c := &connection{
			stop:        make(chan struct{}),
			nextID:      make(chan int32),
			rw:          conn,
			respc:       make(map[int32]chan []byte),
			logger:      &nullLogger{},
			readTimeout: readTimeout,
			apiVersions: make(map[int16]proto.SupportedVersion),
		}
		go c.nextIDLoop()
		go c.readRespLoop()

		if fetchVersions {
			if c.cacheApiVersions() != nil {
				fetchVersions = false
				//required for errorchk
				_ = c.Close()
				continue
			}
		}
		return c, nil
	}

}

func (c *connection) cacheApiVersions() error {
	apiVersions, err := c.APIVersions(&proto.APIVersionsReq{})
	if err != nil {
		c.logger.Debug("cannot fetch apiversions",
			"error", err)
		return err
	}
	for _, api := range apiVersions.APIVersions {
		c.apiVersions[api.APIKey] = api
	}
	return nil
}

//getBestVersion returns version for passed apiKey which best fit server and client requirements
func (c *connection) getBestVersion(apiKey int16) int16 {
	if requested, ok := c.apiVersions[apiKey]; ok {
		supported := proto.SupportedByDriver[apiKey]
		if min(supported.MaxVersion, requested.MaxVersion) >= max(supported.MinVersion, requested.MinVersion) {
			return min(supported.MaxVersion, requested.MaxVersion)
		}
	}
	return 0
}

func min(a int16, b int16) int16 {
	if a < b {
		return a
	}
	return b
}

func max(a int16, b int16) int16 {
	if a > b {
		return a
	}
	return b
}

// nextIDLoop generates correlation IDs, making sure they are always in order
// and within the scope of request-response mapping array.
func (c *connection) nextIDLoop() {
	var id int32 = 1
	for {
		select {
		case <-c.stop:
			close(c.nextID)
			return
		case c.nextID <- id:
			id++
			if id == math.MaxInt32 {
				id = 1
			}
		}
	}
}

// readRespLoop constantly reading response messages from the socket and after
// partial parsing, sends byte representation of the whole message to request
// sending process.
func (c *connection) readRespLoop() {
	defer func() {
		c.mu.Lock()
		for _, cc := range c.respc {
			close(cc)
		}
		c.respc = make(map[int32]chan []byte)
		c.mu.Unlock()
	}()

	rd := bufio.NewReader(c.rw)
	for {
		if c.readTimeout > 0 {
			err := c.rw.SetReadDeadline(time.Now().Add(c.readTimeout))
			if err != nil {
				c.logger.Error("msg", "SetReadDeadline failed",
					"error", err)
			}
		}
		correlationID, b, err := proto.ReadResp(rd)
		if err != nil {
			c.mu.Lock()
			if c.stopErr == nil {
				c.stopErr = err
				close(c.stop)
			}
			c.mu.Unlock()
			return
		}

		c.mu.Lock()
		rc, ok := c.respc[correlationID]
		delete(c.respc, correlationID)
		c.mu.Unlock()
		if !ok {
			c.logger.Warn(
				"msg", "response to unknown request",
				"correlationID", correlationID)
			continue
		}

		select {
		case <-c.stop:
			c.mu.Lock()
			if c.stopErr == nil {
				c.stopErr = ErrClosed
			}
			c.mu.Unlock()
		case rc <- b:
		}
		close(rc)
	}
}

// respWaiter register listener to response message with given correlationID
// and return channel that single response message will be pushed to once it
// will arrive.
// After pushing response message, channel is closed.
//
// Upon connection close, all unconsumed channels are closed.
func (c *connection) respWaiter(correlationID int32) (respc chan []byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopErr != nil {
		return nil, c.stopErr
	}
	if _, ok := c.respc[correlationID]; ok {
		c.logger.Error("msg", "correlation conflict", "correlationID", correlationID)
		return nil, fmt.Errorf("correlation conflict: %d", correlationID)
	}
	respc = make(chan []byte)
	c.respc[correlationID] = respc
	return respc, nil
}

// releaseWaiter removes response channel from waiters pool and close it.
// Calling this method for unknown correlationID has no effect.
func (c *connection) releaseWaiter(correlationID int32) {
	c.mu.Lock()
	rc, ok := c.respc[correlationID]
	if ok {
		delete(c.respc, correlationID)
		close(rc)
	}
	c.mu.Unlock()
}

// Close close underlying transport connection and cancel all pending response
// waiters.
func (c *connection) Close() error {
	c.mu.Lock()
	if c.stopErr == nil {
		c.stopErr = ErrClosed
		close(c.stop)
	}
	c.mu.Unlock()
	return c.rw.Close()
}

func (c *connection) sendRequest(req proto.Request) ([]byte, error) {
	proto.SetVersion(req.GetHeader(), c.getBestVersion(req.Kind()))
	var ok bool
	var correlationID int32
	if correlationID, ok = <-c.nextID; !ok {
		return nil, c.stopErr
	}
	proto.SetCorrelationID(req.GetHeader(), correlationID)

	respc, err := c.respWaiter(req.GetCorrelationID())
	if err != nil {
		c.logger.Error("msg", "failed waiting for response", "error", err)
		return nil, fmt.Errorf("wait for response: %s", err)
	}

	if _, err := req.WriteTo(c.rw); err != nil {
		c.logger.Error("msg", "cannot write", "error", err)
		c.releaseWaiter(req.GetCorrelationID())
		return nil, err
	}
	b, ok := <-respc
	if !ok {
		return nil, c.stopErr
	}
	return b, nil
}

func (c *connection) sendRequestWithoutAcks(req proto.Request) error {
	var ok bool
	var correlationID int32
	if correlationID, ok = <-c.nextID; !ok {
		return c.stopErr
	}
	proto.SetCorrelationID(req.GetHeader(), correlationID)

	proto.SetVersion(req.GetHeader(), c.getBestVersion(req.Kind()))

	_, err := req.WriteTo(c.rw)
	return err
}

// APIVersions sends a request to fetch the supported versions for each API.
// Versioning is only supported in Kafka versions above 0.10.0.0
func (c *connection) APIVersions(req *proto.APIVersionsReq) (*proto.APIVersionsResp, error) {
	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	return proto.ReadVersionedAPIVersionsResp(bytes.NewReader(b), req.GetVersion())
}

// Metadata sends given metadata request to kafka node and returns related
// metadata response.
// Calling this method on closed connection will always return ErrClosed.
func (c *connection) Metadata(req *proto.MetadataReq) (*proto.MetadataResp, error) {
	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	return proto.ReadVersionedMetadataResp(bytes.NewReader(b), req.GetVersion())
}

// CreateTopic sends given createTopic request to kafka node and returns related
// response.
// Calling this method on closed connection will always return ErrClosed.
func (c *connection) CreateTopic(req *proto.CreateTopicsReq) (*proto.CreateTopicsResp, error) {
	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	return proto.ReadCreateTopicsResp(bytes.NewReader(b))
}

// Produce sends given produce request to kafka node and returns related
// response. Sending request with no ACKs flag will result with returning nil
// right after sending request, without waiting for response.
// Calling this method on closed connection will always return ErrClosed.
func (c *connection) Produce(req *proto.ProduceReq) (*proto.ProduceResp, error) {

	if req.RequiredAcks == proto.RequiredAcksNone {
		return nil, c.sendRequestWithoutAcks(req)
	}

	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	return proto.ReadVersionedProduceResp(bytes.NewReader(b), req.GetVersion())
}

// Fetch sends given fetch request to kafka node and returns related response.
// Calling this method on closed connection will always return ErrClosed.
func (c *connection) Fetch(req *proto.FetchReq) (*proto.FetchResp, error) {
	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := proto.ReadVersionedFetchResp(bytes.NewReader(b), req.GetVersion())
	if err != nil {
		return nil, err
	}

	// Compressed messages are returned in full batches for efficiency
	// (the broker doesn't need to decompress).
	// This means that it's possible to get some leading messages
	// with a smaller offset than requested. Trim those.
	for ti := range resp.Topics {
		topic := &resp.Topics[ti]
		reqTopic := &req.Topics[ti]
		for pi := range topic.Partitions {
			partition := &topic.Partitions[pi]
			requestedOffset := reqTopic.Partitions[pi].FetchOffset
			i := 0
			if partition.MessageVersion < 2 {
				for _, msg := range partition.Messages {
					if msg.Offset >= requestedOffset {
						break
					}
					i++
				}
				partition.Messages = partition.Messages[i:]
			} else {
				firstOffset := partition.RecordBatch.FirstOffset
				for _, rec := range partition.RecordBatch.Records {
					if firstOffset+rec.OffsetDelta >= requestedOffset {
						break
					}
					i++
				}
				partition.RecordBatch.Records = partition.RecordBatch.Records[i:]
			}
		}
	}
	return resp, nil
}

// Offset sends given offset request to kafka node and returns related response.
// Calling this method on closed connection will always return ErrClosed.
func (c *connection) Offset(req *proto.OffsetReq) (*proto.OffsetResp, error) {
	// TODO(husio) documentation is not mentioning this directly, but I assume
	// -1 is for non node clients
	req.ReplicaID = -1

	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	return proto.ReadVersionedOffsetResp(bytes.NewReader(b), req.GetVersion())
}

func (c *connection) ConsumerMetadata(req *proto.ConsumerMetadataReq) (*proto.ConsumerMetadataResp, error) {
	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	return proto.ReadVersionedConsumerMetadataResp(bytes.NewReader(b), req.GetVersion())
}

func (c *connection) OffsetCommit(req *proto.OffsetCommitReq) (*proto.OffsetCommitResp, error) {
	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	return proto.ReadVersionedOffsetCommitResp(bytes.NewReader(b), req.GetVersion())
}

func (c *connection) OffsetFetch(req *proto.OffsetFetchReq) (*proto.OffsetFetchResp, error) {
	b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	return proto.ReadVersionedOffsetFetchResp(bytes.NewReader(b), req.GetVersion())
}
