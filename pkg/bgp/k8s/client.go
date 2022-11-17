// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package k8s provides a Kubernetes client to be used with MetalLB
// integration.
package k8s

import (
	"context"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/client"
)

func New(l *logrus.Logger, cs client.Clientset) *Client {
	return &Client{
		Clientset: cs,
		log:       l,
	}
}

// Client wraps the K8s client so that it can conform to the client from
// MetalLB.
type Client struct {
	client.Clientset

	log *logrus.Logger
}

func (c *Client) Update(svc *v1.Service) (*v1.Service, error) {
	return c.CoreV1().Services(svc.GetNamespace()).Update(context.TODO(), svc, metav1.UpdateOptions{})
}
func (c *Client) UpdateStatus(svc *v1.Service) error {
	_, err := c.CoreV1().Services(svc.GetNamespace()).UpdateStatus(context.TODO(), svc, metav1.UpdateOptions{})
	return err
}

func (c *Client) Infof(_ *v1.Service, desc, fmt string, args ...interface{}) {
	c.log.WithField("event", desc).Infof(fmt, args...)
}
func (c *Client) Errorf(_ *v1.Service, desc, fmt string, args ...interface{}) {
	c.log.WithField("event", desc).Errorf(fmt, args...)
}
