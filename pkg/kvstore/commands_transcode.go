// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"encoding/json"
	"strings"
)

type TranscodableJSON interface {
	Marshal() ([]byte, error)
	Unmarshal(key string, data []byte) error

	json.Marshaler
	json.Unmarshaler
}

type TranscodableCreator func() TranscodableJSON

type transcoder struct {
	prefix  string
	creator TranscodableCreator
}

func (t transcoder) transcodeToJSON(key string, value []byte) ([]byte, error) {
	val := t.creator()
	if err := val.Unmarshal(strings.TrimPrefix(key, t.prefix), value); err != nil {
		return nil, err
	}
	return val.MarshalJSON()
}

func (t transcoder) transcodeFromJSON(value []byte) ([]byte, error) {
	val := t.creator()
	if err := val.UnmarshalJSON(value); err != nil {
		return nil, err
	}
	return val.Marshal()
}

var transcoders []transcoder

func RegisterCommandTranscoder(creator TranscodableCreator, prefixes ...string) {
	for _, prefix := range prefixes {
		transcoders = append(
			transcoders,
			transcoder{
				creator: creator,
				prefix:  strings.TrimRight(prefix, "/") + "/",
			},
		)
	}
}

func tryTranscodeToJSON(key string, value []byte) ([]byte, error) {
	for _, transcoder := range transcoders {
		if !strings.HasPrefix(key, transcoder.prefix) {
			continue
		}
		return transcoder.transcodeToJSON(key, value)
	}

	return value, nil
}

func tryTranscodeFromJSON(key string, value []byte) ([]byte, error) {
	for _, transcoder := range transcoders {
		if !strings.HasPrefix(key, transcoder.prefix) {
			continue
		}
		return transcoder.transcodeFromJSON(value)
	}

	return value, nil
}
