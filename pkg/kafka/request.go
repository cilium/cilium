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

	"github.com/optiopay/kafka/proto"
	log "github.com/sirupsen/logrus"
)

// RequestMessage represents a Kafka request message
type RequestMessage struct {
	kind    int16
	version int16
	rawMsg  []byte
	request interface{}
}

// GetKind returns the kind of Kafka request
func (req *RequestMessage) GetKind() int16 {
	return req.kind
}

// GetRaw returns the raw Kafka request
func (req *RequestMessage) GetRaw() []byte {
	return req.rawMsg
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

// CreateResponse creates a response message based on the provided request
// message. The response will have the specified error code set in all topics
// and embedded partitions.
func (req *RequestMessage) CreateResponse(err error) (*ResponseMessage, error) {
	if req == nil || req.request == nil {
		return nil, fmt.Errorf("request is nil")
	}

	// FIXME: Send response versions based on request

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
	}

	return nil, fmt.Errorf("unknown request type %d", req.kind)
}

func (req *RequestMessage) getVersion() int16 {
	return int16(binary.BigEndian.Uint16(req.rawMsg[6:8]))
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

	req.version = req.getVersion()

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
	}

	if err != nil {
		log.WithFields(log.Fields{
			fieldRequest: req.String(),
		}).WithError(err).Debug("Ignoring Kafka message due to parse error")
	}

	return req, nil
}
