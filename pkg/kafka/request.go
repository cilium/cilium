// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kafka

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/flowdebug"

	"github.com/optiopay/kafka/proto"
)

// RequestMessage represents a Kafka request message
type RequestMessage struct {
	kind    int16
	version int16
	rawMsg  []byte
	request interface{}
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

	switch val := req.request.(type) {
	case *proto.ProduceReq:
		return produceTopics(val)
	case *proto.FetchReq:
		return fetchTopics(val)
	case *proto.OffsetReq:
		return offsetTopics(val)
	case *proto.MetadataReq:
		return metadataTopics(val)
	case *proto.OffsetCommitReq:
		return offsetCommitTopics(val)
	case *proto.OffsetFetchReq:
		return offsetFetchTopics(val)
	}
	return nil
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
		log.Panic(fmt.Sprintf("Kafka API key not handled: %d", req.kind))
	}
	return nil, nil
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
		return nil,
			fmt.Errorf("unexpected end of request (length < 12 bytes)")
	}
	req.version = req.extractVersion()

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
		log.WithField(fieldRequest, req.String()).Debugf("Unknown Kafka request API key: %d", req.kind)
	}

	if err != nil {
		flowdebug.Log(log.WithField(fieldRequest, req.String()).WithError(err),
			"Ignoring Kafka message due to parse error")
		return nil, err
	}
	return req, nil
}
