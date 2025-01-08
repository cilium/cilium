// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package limits

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/sirupsen/logrus"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "aws-eni-limits")
)

const (
	EC2apiRetryCount   = 2
	EC2apiTimeout      = time.Second * 5
	TriggerMinInterval = time.Minute
)

type ec2API interface {
	GetInstanceTypes(context.Context) ([]ec2_types.InstanceTypeInfo, error)
}
type LimitsGetter struct {
	lock.RWMutex
	m                   map[string]ipamTypes.Limits
	limitsUpdateTrigger *trigger.Trigger
	lastUpdate          time.Time
	triggerMinInterval  time.Duration
	ec2APITimeout       time.Duration
	ec2APIRetryCount    int
	triggerDone         chan struct{}
}

func NewLimitsGetter(api ec2API, triggerMinInterval, ec2APITimeout time.Duration, ec2APIRetryCount int) (*LimitsGetter, error) {
	l := &LimitsGetter{
		triggerDone: make(chan struct{}),
		m:           make(map[string]ipamTypes.Limits),
	}
	err := l.initEC2APIUpdateTrigger(api, triggerMinInterval, ec2APITimeout, ec2APIRetryCount)
	if err != nil {
		log.WithError(err).Warning("Unable to initialize EC2 API update trigger")
		return nil, err
	}
	return l, nil
}

// Get returns the instance limits of a particular instance type.
func (l *LimitsGetter) Get(instanceType string) (ipamTypes.Limits, bool) {

	l.RLock()
	if limit, ok := l.m[instanceType]; ok {
		l.RUnlock()
		log.WithFields(logrus.Fields{
			"limit":        limit,
			"instanceType": instanceType,
		}).Debug("Get limits from cache")
		return limit, true
	}
	minInterval := l.triggerMinInterval
	ec2apiTimeoutWithJitter := l.ec2APITimeout + time.Duration(float64(l.ec2APITimeout)*0.1)
	lastUpdate := l.lastUpdate
	currentDone := l.triggerDone
	l.RUnlock()
	// If the update happened less than minInterval ago and Get() is called again within internal
	// but cannot get the limits from cache, it will not trigger the update and wait at select to
	// get the timeout. To avoid waiting for the unnecessary timeout, we will simply return false
	//since the limits are not updated yet.
	if time.Since(lastUpdate) < minInterval {
		log.Debug("Can't trigger update and return false")
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
		log.Debug("Get limits from cache after update")
		return limit, ok
	case <-time.After(ec2apiTimeoutWithJitter):
		log.WithField("instanceType", instanceType).Warning("Failed to get instance limits from EC2 API after timeout")
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

	return nil
}

func (l *LimitsGetter) newLimitsUpdateTrigger(api ec2API, minInterval, timeout time.Duration, retryCount int) (*trigger.Trigger, error) {
	return trigger.NewTrigger(trigger.Parameters{
		Name:        "ec2-instance-limits-update",
		MinInterval: minInterval,
		TriggerFunc: func(reasons []string) {
			log.WithField("triggerReasons", reasons).Debug("Starting limits update")
			if err := l.updateFromEC2APIWithRetry(context.TODO(), api, timeout, retryCount); err != nil {
				log.WithError(err).Warning("Failed to update instance limits from EC2 API")
			}

			l.Lock()
			l.lastUpdate = time.Now()
			oldDone := l.triggerDone
			l.triggerDone = make(chan struct{})
			l.Unlock()
			if oldDone != nil {
				close(oldDone)
			}
			log.Debug("Limits update completed through trigger")
		},
	})
}

func (l *LimitsGetter) initEC2APIUpdateTrigger(api ec2API, triggerMinInterval, ec2APITimeout time.Duration, ec2APIRetryCount int) error {
	l.Lock()
	l.triggerMinInterval = triggerMinInterval
	l.ec2APITimeout = ec2APITimeout
	l.ec2APIRetryCount = ec2APIRetryCount
	l.Unlock()

	t, err := l.newLimitsUpdateTrigger(api, triggerMinInterval, ec2APITimeout, ec2APIRetryCount)
	if err != nil {
		log.WithError(err).Warning("Failed to create EC2 update trigger")
		return err
	}

	l.Lock()
	l.limitsUpdateTrigger = t
	l.Unlock()

	if err := l.updateFromEC2APIWithRetry(context.Background(), api, ec2APITimeout, ec2APIRetryCount); err != nil {
		log.WithError(err).Warning("Failed initial EC2 API limits update")
		return err
	}
	log.Info("Initial EC2 API limits update completed successfully")

	l.Lock()
	l.lastUpdate = time.Now()
	l.Unlock()

	return nil
}

func (l *LimitsGetter) updateFromEC2APIWithRetry(ctx context.Context, api ec2API, timeout time.Duration, retryCount int) error {

	return resiliency.Retry(ctx,
		timeout,
		retryCount,
		func(ctx context.Context, retries int) (bool, error) {
			err := l.updateFromEC2API(ctx, api)
			if err != nil {
				log.WithFields(logrus.Fields{
					"error": err,
					"retry": retries,
				}).Debug("Retrying EC2 API limits update")
				return false, nil
			}
			return true, nil
		},
	)
}
