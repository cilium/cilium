// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kafka

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cilium/kafka/proto"
)

// ResponseMessage represents a Kafka response message.
type ResponseMessage struct {
	rawMsg   []byte
	response interface{}
}

// GetCorrelationID returns the Kafka request correlationID
func (res *ResponseMessage) GetCorrelationID() CorrelationID {
	if len(res.rawMsg) >= 8 {
		return CorrelationID(binary.BigEndian.Uint32(res.rawMsg[4:8]))
	}

	return CorrelationID(0)
}

// SetCorrelationID modified the correlation ID of the Kafka request
func (res *ResponseMessage) SetCorrelationID(id CorrelationID) {
	if len(res.rawMsg) >= 8 {
		binary.BigEndian.PutUint32(res.rawMsg[4:8], uint32(id))
	}
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
				ID:                  partition.ID,
				Err:                 err,
				AbortedTransactions: nil, // nullable
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
				ID:      partition.ID,
				Err:     err,
				Offsets: make([]int64, 0), // Not nullable, so must never be nil.
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

	var topics []proto.MetadataRespTopic
	if req.Topics != nil {
		topics = make([]proto.MetadataRespTopic, len(req.Topics))
	}
	resp := &proto.MetadataResp{
		CorrelationID: req.CorrelationID,
		Brokers:       make([]proto.MetadataRespBroker, 0), // Not nullable, so must never be nil.
		Topics:        topics,
	}

	for k, topic := range req.Topics {
		resp.Topics[k] = proto.MetadataRespTopic{
			Name:       topic,
			Err:        err,
			Partitions: make([]proto.MetadataRespPartition, 0), // Not nullable, so must never be nil.
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

	var topics []proto.OffsetFetchRespTopic
	if req.Topics != nil {
		topics = make([]proto.OffsetFetchRespTopic, len(req.Topics))
	}
	resp := &proto.OffsetFetchResp{
		CorrelationID: req.CorrelationID,
		Topics:        topics,
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
