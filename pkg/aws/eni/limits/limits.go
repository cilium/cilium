// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package limits

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	EC2apiRetryCount   = 2
	EC2apiTimeout      = time.Second * 5
	TriggerMinInterval = time.Minute
)

var subsysLogAttr = []any{logfields.LogSubsys, "aws-eni-limits"}

type ec2API interface {
	GetInstanceTypes(context.Context) ([]ec2_types.InstanceTypeInfo, error)
}
type LimitsGetter struct {
	lock.RWMutex
	m                   map[string]ipamTypes.Limits
	logger              *slog.Logger
	limitsUpdateTrigger *trigger.Trigger
	lastUpdate          time.Time
	triggerMinInterval  time.Duration
	ec2APITimeout       time.Duration
	ec2APIRetryCount    int
	triggerDone         chan struct{}
}

func NewLimitsGetter(logger *slog.Logger, api ec2API, triggerMinInterval, ec2APITimeout time.Duration, ec2APIRetryCount int) (*LimitsGetter, error) {
	l := &LimitsGetter{
		logger:      logger.With(subsysLogAttr...),
		triggerDone: make(chan struct{}),
		m:           make(map[string]ipamTypes.Limits),
	}
	err := l.initEC2APIUpdateTrigger(api, triggerMinInterval, ec2APITimeout, ec2APIRetryCount)
	if err != nil {
		l.logger.Error("Unable to initialize EC2 API update trigger", logfields.Error, err)
		return nil, err
	}
	return l, nil
}

// Get returns the instance limits of a particular instance type.
func (l *LimitsGetter) Get(instanceType string) (ipamTypes.Limits, bool) {

	l.RLock()
	if limit, ok := l.m[instanceType]; ok {
		l.RUnlock()
		l.logger.Debug("Get limits from cache",
			logfields.Limit, limit,
			logfields.InstanceType, instanceType)
		return limit, true
	}
	minInterval := l.triggerMinInterval
	ec2apiTimeoutWithJitter := l.ec2APITimeout + time.Duration(float64(l.ec2APITimeout)*0.1)
	lastUpdate := l.lastUpdate
	currentDone := l.triggerDone
	l.RUnlock()
	// If the update happened less than minInterval ago and Get() is called again within interval
	// but cannot get the limits from cache, it will not trigger the update and wait at select to
	// get the timeout. To avoid waiting for the unnecessary timeout, we will simply return false
	// since the limits are not updated yet.
	if time.Since(lastUpdate) < minInterval {
		return ipamTypes.Limits{}, false
	}

	l.limitsUpdateTrigger.Trigger()
	// If the update is happening but not finished, all the Get() calls will get into select and
	// wait for the closing of the triggerDone channel.
	select {
	case <-currentDone:
		l.RLock()
		defer l.RUnlock()
		limit, ok := l.m[instanceType]
		l.logger.Debug("Get limits from cache after update",
			logfields.Limit, limit,
			logfields.InstanceType, instanceType)
		return limit, ok
	case <-time.After(ec2apiTimeoutWithJitter):
		l.logger.Debug("Failed to get instance limits from EC2 API after timeout", logfields.InstanceType, instanceType)
		return ipamTypes.Limits{}, false
	}
}

// updateFromEC2API updates limits from the EC2 API via calling
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceTypes.html.
func (l *LimitsGetter) updateFromEC2API(ctx context.Context, api ec2API) error {

	instanceTypeInfos, err := api.GetInstanceTypes(ctx)
	if err != nil {
		return err
	}
	l.Lock()
	defer l.Unlock()

	for _, instanceTypeInfo := range instanceTypeInfos {
		instanceType := string(instanceTypeInfo.InstanceType)
		adapterLimit := aws.ToInt32(instanceTypeInfo.NetworkInfo.MaximumNetworkInterfaces)
		ipv4PerAdapter := aws.ToInt32(instanceTypeInfo.NetworkInfo.Ipv4AddressesPerInterface)
		ipv6PerAdapter := aws.ToInt32(instanceTypeInfo.NetworkInfo.Ipv6AddressesPerInterface)
		hypervisorType := instanceTypeInfo.Hypervisor

		l.m[instanceType] = ipamTypes.Limits{
			Adapters:       int(adapterLimit),
			IPv4:           int(ipv4PerAdapter),
			IPv6:           int(ipv6PerAdapter),
			HypervisorType: string(hypervisorType),
		}
	}
	l.lastUpdate = time.Now()
	return nil
}

func (l *LimitsGetter) newLimitsUpdateTrigger(api ec2API, minInterval, timeout time.Duration, retryCount int) (*trigger.Trigger, error) {
	return trigger.NewTrigger(trigger.Parameters{
		Name:        "ec2-instance-limits-update",
		MinInterval: minInterval,
		TriggerFunc: func(reasons []string) {
			if err := l.updateFromEC2APIWithRetry(context.TODO(), api, timeout, retryCount); err != nil {
				l.logger.Error("Failed to update instance limits from EC2 API", logfields.Error, err)
			}

			l.Lock()
			l.lastUpdate = time.Now()
			oldDone := l.triggerDone
			l.triggerDone = make(chan struct{})
			l.Unlock()
			if oldDone != nil {
				close(oldDone)
			}
		},
	})
}

func (l *LimitsGetter) initEC2APIUpdateTrigger(api ec2API, triggerMinInterval, ec2APITimeout time.Duration, ec2APIRetryCount int) error {
	l.Lock()
	l.triggerMinInterval = triggerMinInterval
	l.ec2APITimeout = ec2APITimeout
	l.ec2APIRetryCount = ec2APIRetryCount

	t, err := l.newLimitsUpdateTrigger(api, triggerMinInterval, ec2APITimeout, ec2APIRetryCount)
	if err != nil {
		l.logger.Error("Failed to create EC2 update trigger", logfields.Error, err)
		return err
	}

	l.limitsUpdateTrigger = t
	l.Unlock()

	if err := l.updateFromEC2APIWithRetry(context.Background(), api, ec2APITimeout, ec2APIRetryCount); err != nil {
		l.logger.Error("Failed initial EC2 API limits update", logfields.Error, err)
		return err
	}
	l.logger.Info("Initial EC2 API limits update completed successfully")

	return nil
}

func (l *LimitsGetter) updateFromEC2APIWithRetry(ctx context.Context, api ec2API, timeout time.Duration, retryCount int) error {

	return resiliency.Retry(ctx,
		timeout,
		retryCount,
		func(ctx context.Context, retries int) (bool, error) {
			err := l.updateFromEC2API(ctx, api)
			if err != nil {
				return false, nil
			}
			return true, nil
		},
	)
}
