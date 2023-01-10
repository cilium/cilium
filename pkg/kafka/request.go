// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kafka

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cilium/kafka/proto"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/flowdebug"
)

// RequestMessage represents a Kafka request message
type RequestMessage struct {
	kind     int16
	version  int16
	clientID string
	rawMsg   []byte
	request  interface{}
	// Maintain a map of all topics in the request.  We should
	// allow the request only if all topics in the request are
	// allowed by the rules.
	topics map[string]struct{}
}

// CorrelationID represents the correlation id as defined in the Kafka protocol
// specification
type CorrelationID uint32

// GetAPIKey returns the kind of Kafka request
func (req *RequestMessage) GetAPIKey() int16 {
	return req.kind
}

// GetRaw returns the raw Kafka request
func (req *RequestMessage) GetRaw() []byte {
	return req.rawMsg
}

// GetVersion returns the version Kafka request
func (req *RequestMessage) GetVersion() int16 {
	return req.version
}

// GetCorrelationID returns the Kafka request correlationID
func (req *RequestMessage) GetCorrelationID() CorrelationID {
	if len(req.rawMsg) >= 12 {
		return CorrelationID(binary.BigEndian.Uint32(req.rawMsg[8:12]))
	}

	return CorrelationID(0)
}

// SetCorrelationID modified the correlation ID of the Kafka request
func (req *RequestMessage) SetCorrelationID(id CorrelationID) {
	if len(req.rawMsg) >= 12 {
		binary.BigEndian.PutUint32(req.rawMsg[8:12], uint32(id))
	}
}

func (req *RequestMessage) extractVersion() int16 {
	return int16(binary.BigEndian.Uint16(req.rawMsg[6:8]))
}

func (req *RequestMessage) extractClientID() string {
	if req.version == 0 || len(req.rawMsg) < 14 {
		return "" // 0 version has no client ID
	}
	// ref. https://kafka.apache.org/protocol#protocol_details
	length := int16(binary.BigEndian.Uint16(req.rawMsg[12:14]))
	if length <= 0 || len(req.rawMsg) < 14+int(length) {
		return ""
	}
	return string(req.rawMsg[14 : 14+int(length)])
}

// String returns a human readable representation of the request message
func (req *RequestMessage) String() string {
	b, err := json.Marshal(req.request)
	if err != nil {
		return err.Error()
	}

	return fmt.Sprintf("apiKey=%d,apiVersion=%d,len=%d: %s",
		req.kind, req.version, len(req.rawMsg), string(b))
}

// GetTopics returns the Kafka request list of topics
func (req *RequestMessage) GetTopics() []string {
	if req.request == nil {
		return nil
	}
	topics := make([]string, 0, len(req.topics))
	for topic := range req.topics {
		topics = append(topics, topic)
	}
	return topics
}

func (req *RequestMessage) setTopics() {
	var topics []string
	switch val := req.request.(type) {
	case *proto.ProduceReq:
		topics = produceTopics(val)
	case *proto.FetchReq:
		topics = fetchTopics(val)
	case *proto.OffsetReq:
		topics = offsetTopics(val)
	case *proto.MetadataReq:
		topics = metadataTopics(val)
	case *proto.OffsetCommitReq:
		topics = offsetCommitTopics(val)
	case *proto.OffsetFetchReq:
		topics = offsetFetchTopics(val)
	}
	req.topics = make(map[string]struct{}, len(topics))
	for _, topic := range topics {
		req.topics[topic] = struct{}{}
	}
}

func produceTopics(req *proto.ProduceReq) []string {
	topics := make([]string, len(req.Topics))
	for k, topic := range req.Topics {
		topics[k] = topic.Name
	}
	return topics
}

func fetchTopics(req *proto.FetchReq) []string {
	topics := make([]string, len(req.Topics))
	for k, topic := range req.Topics {
		topics[k] = topic.Name
	}
	return topics
}

func offsetTopics(req *proto.OffsetReq) []string {
	topics := make([]string, len(req.Topics))
	for k, topic := range req.Topics {
		topics[k] = topic.Name
	}
	return topics
}

func metadataTopics(req *proto.MetadataReq) []string {
	topics := req.Topics
	return topics
}

func offsetCommitTopics(req *proto.OffsetCommitReq) []string {
	topics := make([]string, len(req.Topics))
	for k, topic := range req.Topics {
		topics[k] = topic.Name
	}
	return topics
}

func offsetFetchTopics(req *proto.OffsetFetchReq) []string {
	topics := make([]string, len(req.Topics))
	for k, topic := range req.Topics {
		topics[k] = topic.Name
	}
	return topics
}

// CreateResponse creates a response message based on the provided request
// message. The response will have the specified error code set in all topics
// and embedded partitions.
func (req *RequestMessage) CreateResponse(err error) (*ResponseMessage, error) {
	switch val := req.request.(type) {
	case *proto.ProduceReq:
		return createProduceResponse(val, err)
	case *proto.FetchReq:
		return createFetchResponse(val, err)
	case *proto.OffsetReq:
		return createOffsetResponse(val, err)
	case *proto.MetadataReq:
		return createMetadataResponse(val, err)
	case *proto.ConsumerMetadataReq:
		return createConsumerMetadataResponse(val, err)
	case *proto.OffsetCommitReq:
		return createOffsetCommitResponse(val, err)
	case *proto.OffsetFetchReq:
		return createOffsetFetchResponse(val, err)
	case nil:
		return nil, fmt.Errorf("unsupported request API key %d", req.kind)
	default:
		// The switch cases above must correspond exactly to the switch cases
		// in ReadRequest.
		logrus.Panic(fmt.Sprintf("Kafka API key not handled: %d", req.kind))
	}
	return nil, nil
}

// CreateAuthErrorResponse creates Authorization error response message for 'req'
func (req *RequestMessage) CreateAuthErrorResponse() (*ResponseMessage, error) {
	return req.CreateResponse(proto.ErrTopicAuthorizationFailed)
}

// ReadRequest will read a Kafka request from an io.Reader and return the
// message or an error.
func ReadRequest(reader io.Reader) (*RequestMessage, error) {
	req := &RequestMessage{}
	var err error

	req.kind, req.rawMsg, err = proto.ReadReq(reader)
	if err != nil {
		return nil, err
	}

	if len(req.rawMsg) < 12 {
		return nil, fmt.Errorf("unexpected end of request (length < 12 bytes)")
	}
	req.version = req.extractVersion()
	req.clientID = req.extractClientID()

	var nilSlice []byte
	buf := bytes.NewBuffer(append(nilSlice, req.rawMsg...))

	switch req.kind {
	case proto.ProduceReqKind:
		req.request, err = proto.ReadProduceReq(buf)
	case proto.FetchReqKind:
		req.request, err = proto.ReadFetchReq(buf)
	case proto.OffsetReqKind:
		req.request, err = proto.ReadOffsetReq(buf)
	case proto.MetadataReqKind:
		req.request, err = proto.ReadMetadataReq(buf)
	case proto.ConsumerMetadataReqKind:
		req.request, err = proto.ReadConsumerMetadataReq(buf)
	case proto.OffsetCommitReqKind:
		req.request, err = proto.ReadOffsetCommitReq(buf)
	case proto.OffsetFetchReqKind:
		req.request, err = proto.ReadOffsetFetchReq(buf)
	default:
		if flowdebug.Enabled() {
			logrus.Debugf("Unknown Kafka request API key: %d in %s", req.kind, req.String())
		}
	}

	if err != nil {
		if flowdebug.Enabled() {
			logrus.WithError(err).Debugf("Ignoring Kafka message %s due to parse error", req.String())
		}
		return nil, err
	}

	req.setTopics()

	return req, nil
}
