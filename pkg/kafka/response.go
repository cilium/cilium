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
	"encoding/json"
	"fmt"

	"github.com/optiopay/kafka/proto"
	"io"
)

// ResponseMessage represents a Kafka response message.
type ResponseMessage struct {
	rawMsg   []byte
	response interface{}
}

// GetRaw returns the raw Kafka response
func (res *ResponseMessage) GetRaw() []byte {
	return res.rawMsg
}

// String returns a human readable representation of the response message
func (res *ResponseMessage) String() string {
	b, err := json.Marshal(res.response)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// ReadResponse will read a Kafka response from an io.Reader and return the
// message or an error.
func ReadResponse(reader io.Reader) (*ResponseMessage, error) {
	rsp := &ResponseMessage{}
	var err error

	_, rsp.rawMsg, err = proto.ReadResp(reader)
	if err != nil {
		return nil, err
	}

	if len(rsp.rawMsg) < 6 {
		return nil,
			fmt.Errorf("unexpected end of response (length < 6 bytes)")
	}

	return rsp, nil
}

func createProduceResponse(req *proto.ProduceReq, err error) (*ResponseMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	resp := &proto.ProduceResp{
		CorrelationID: req.CorrelationID,
		Topics:        make([]proto.ProduceRespTopic, len(req.Topics)),
	}

	for k, topic := range req.Topics {
		resp.Topics[k] = proto.ProduceRespTopic{
			Name:       topic.Name,
			Partitions: make([]proto.ProduceRespPartition, len(topic.Partitions)),
		}

		for k2, partition := range topic.Partitions {
			resp.Topics[k].Partitions[k2] = proto.ProduceRespPartition{
				ID:  partition.ID,
				Err: err,
			}
		}
	}

	b, err := resp.Bytes(req.Version)
	if err != nil {
		return nil, err
	}

	return &ResponseMessage{
		response: resp,
		rawMsg:   b,
	}, nil
}

func createFetchResponse(req *proto.FetchReq, err error) (*ResponseMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	resp := &proto.FetchResp{
		CorrelationID: req.CorrelationID,
		Topics:        make([]proto.FetchRespTopic, len(req.Topics)),
	}

	for k, topic := range req.Topics {
		resp.Topics[k] = proto.FetchRespTopic{
			Name:       topic.Name,
			Partitions: make([]proto.FetchRespPartition, len(topic.Partitions)),
		}

		for k2, partition := range topic.Partitions {
			resp.Topics[k].Partitions[k2] = proto.FetchRespPartition{
				ID:  partition.ID,
				Err: err,
			}
		}
	}

	b, err := resp.Bytes(req.Version)
	if err != nil {
		return nil, err
	}

	return &ResponseMessage{
		response: resp,
		rawMsg:   b,
	}, nil
}

func createOffsetResponse(req *proto.OffsetReq, err error) (*ResponseMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	resp := &proto.OffsetResp{
		CorrelationID: req.CorrelationID,
		Topics:        make([]proto.OffsetRespTopic, len(req.Topics)),
	}

	for k, topic := range req.Topics {
		resp.Topics[k] = proto.OffsetRespTopic{
			Name:       topic.Name,
			Partitions: make([]proto.OffsetRespPartition, len(topic.Partitions)),
		}

		for k2, partition := range topic.Partitions {
			resp.Topics[k].Partitions[k2] = proto.OffsetRespPartition{
				ID:  partition.ID,
				Err: err,
			}
		}
	}

	b, err := resp.Bytes(req.Version)
	if err != nil {
		return nil, err
	}

	return &ResponseMessage{
		response: resp,
		rawMsg:   b,
	}, nil
}

func createMetadataResponse(req *proto.MetadataReq, err error) (*ResponseMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	resp := &proto.MetadataResp{
		CorrelationID: req.CorrelationID,
		Topics:        make([]proto.MetadataRespTopic, len(req.Topics)),
	}

	for k, topic := range req.Topics {
		resp.Topics[k] = proto.MetadataRespTopic{
			Name: topic,
			Err:  err,
		}
	}

	b, err := resp.Bytes(req.Version)
	if err != nil {
		return nil, err
	}

	return &ResponseMessage{
		response: resp,
		rawMsg:   b,
	}, nil
}

func createConsumerMetadataResponse(req *proto.ConsumerMetadataReq, err error) (*ResponseMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	resp := &proto.ConsumerMetadataResp{
		CorrelationID: req.CorrelationID,
		Err:           err,
	}

	b, err := resp.Bytes(req.Version)
	if err != nil {
		return nil, err
	}

	return &ResponseMessage{
		response: resp,
		rawMsg:   b,
	}, nil
}

func createOffsetCommitResponse(req *proto.OffsetCommitReq, err error) (*ResponseMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	resp := &proto.OffsetCommitResp{
		CorrelationID: req.CorrelationID,
		Topics:        make([]proto.OffsetCommitRespTopic, len(req.Topics)),
	}

	for k, topic := range req.Topics {
		resp.Topics[k] = proto.OffsetCommitRespTopic{
			Name:       topic.Name,
			Partitions: make([]proto.OffsetCommitRespPartition, len(topic.Partitions)),
		}

		for k2, partition := range topic.Partitions {
			resp.Topics[k].Partitions[k2] = proto.OffsetCommitRespPartition{
				ID:  partition.ID,
				Err: err,
			}
		}
	}

	b, err := resp.Bytes(req.Version)
	if err != nil {
		return nil, err
	}

	return &ResponseMessage{
		response: resp,
		rawMsg:   b,
	}, nil
}

func createOffsetFetchResponse(req *proto.OffsetFetchReq, err error) (*ResponseMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	resp := &proto.OffsetFetchResp{
		CorrelationID: req.CorrelationID,
		Topics:        make([]proto.OffsetFetchRespTopic, len(req.Topics)),
	}

	for k, topic := range req.Topics {
		resp.Topics[k] = proto.OffsetFetchRespTopic{
			Name:       topic.Name,
			Partitions: make([]proto.OffsetFetchRespPartition, len(topic.Partitions)),
		}

		for k2, partition := range topic.Partitions {
			resp.Topics[k].Partitions[k2] = proto.OffsetFetchRespPartition{
				ID:  partition,
				Err: err,
			}
		}
	}

	b, err := resp.Bytes(req.Version)
	if err != nil {
		return nil, err
	}

	return &ResponseMessage{
		response: resp,
		rawMsg:   b,
	}, nil
}
