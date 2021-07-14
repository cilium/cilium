// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/client/recorder"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

func (c *Client) GetRecorder() ([]*models.Recorder, error) {
	resp, err := c.Recorder.GetRecorder(nil)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

func (c *Client) GetRecorderMasks() ([]*models.RecorderMask, error) {
	resp, err := c.Recorder.GetRecorderMasks(nil)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

func (c *Client) GetRecorderID(id int64) (*models.Recorder, error) {
	params := recorder.NewGetRecorderIDParams().WithID(id).WithTimeout(api.ClientTimeout)
	resp, err := c.Recorder.GetRecorderID(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

func (c *Client) PutRecorderID(id int64, rec *models.RecorderSpec) (bool, error) {
	params := recorder.NewPutRecorderIDParams().WithID(id).WithConfig(rec).WithTimeout(api.ClientTimeout)
	_, created, err := c.Recorder.PutRecorderID(params)
	return created != nil, Hint(err)
}

func (c *Client) DeleteRecorderID(id int64) error {
	params := recorder.NewDeleteRecorderIDParams().WithID(id).WithTimeout(api.ClientTimeout)
	_, err := c.Recorder.DeleteRecorderID(params)
	return Hint(err)
}
