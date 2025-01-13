// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package limits

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

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

var limits struct {
	lock.RWMutex
	m                   map[string]ipamTypes.Limits
	limitsUpdateTrigger *trigger.Trigger
	lastUpdate          time.Time
	triggerMinInterval  time.Duration
	ec2APITimeout       time.Duration
	ec2APIRetryCount    int
	triggerDone         chan struct{}
}

func init() {
	limits.m = make(map[string]ipamTypes.Limits)
	limits.triggerDone = make(chan struct{})
}

// Get returns the instance limits of a particular instance type.
func Get(instanceType string, api ec2API) (ipamTypes.Limits, bool) {

	limits.RLock()
	if limit, ok := limits.m[instanceType]; ok {
		limits.RUnlock()
		return limit, true
	}
	minInterval := limits.triggerMinInterval
	ec2apiTimeoutWithJitter := limits.ec2APITimeout + time.Duration(float64(limits.ec2APITimeout)*0.1)
	lastUpdate := limits.lastUpdate
	limits.RUnlock()

	if time.Since(lastUpdate) < minInterval || lastUpdate.IsZero() {
		return ipamTypes.Limits{}, false
	}

	// If not found, try to update from EC2 API
	limits.limitsUpdateTrigger.Trigger()

	select {
	case <-GetTriggerDone():
		limits.RLock()
		defer limits.RUnlock()
		limit, ok := limits.m[instanceType]
		return limit, ok
	case <-time.After(ec2apiTimeoutWithJitter):
		log.WithField("instanceType", instanceType).Warning("Failed to get instance limits from EC2 API after timeout")
		return ipamTypes.Limits{}, false
	}
}

// UpdateFromUserDefinedMappings updates limits from the given map.
func UpdateFromUserDefinedMappings(m map[string]string) (err error) {
	limits.Lock()
	defer limits.Unlock()

	for instanceType, limitString := range m {
		limit, err := parseLimitString(limitString)
		if err != nil {
			return err
		}
		// Add or overwrite limits
		limits.m[instanceType] = limit
	}
	return nil
}

type ec2API interface {
	GetInstanceTypes(context.Context) ([]ec2_types.InstanceTypeInfo, error)
}

// UpdateFromEC2API updates limits from the EC2 API via calling
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceTypes.html.
func UpdateFromEC2API(ctx context.Context, api ec2API) error {

	instanceTypeInfos, err := api.GetInstanceTypes(ctx)
	if err != nil {
		return err
	}
	limits.Lock()
	defer limits.Unlock()

	for _, instanceTypeInfo := range instanceTypeInfos {
		instanceType := string(instanceTypeInfo.InstanceType)
		adapterLimit := aws.ToInt32(instanceTypeInfo.NetworkInfo.MaximumNetworkInterfaces)
		ipv4PerAdapter := aws.ToInt32(instanceTypeInfo.NetworkInfo.Ipv4AddressesPerInterface)
		ipv6PerAdapter := aws.ToInt32(instanceTypeInfo.NetworkInfo.Ipv6AddressesPerInterface)
		hypervisorType := instanceTypeInfo.Hypervisor

		limits.m[instanceType] = ipamTypes.Limits{
			Adapters:       int(adapterLimit),
			IPv4:           int(ipv4PerAdapter),
			IPv6:           int(ipv6PerAdapter),
			HypervisorType: string(hypervisorType),
		}
	}

	return nil
}

// parseLimitString returns the Limits struct parsed from config string.
func parseLimitString(limitString string) (limit ipamTypes.Limits, err error) {
	intSlice := make([]int, 3)
	stringSlice := strings.Split(strings.ReplaceAll(limitString, " ", ""), ",")
	if len(stringSlice) != 3 {
		return limit, fmt.Errorf("invalid limit value")
	}
	for i, s := range stringSlice {
		intLimit, err := strconv.Atoi(s)
		if err != nil {
			return limit, err
		}
		intSlice[i] = intLimit
	}
	return ipamTypes.Limits{Adapters: intSlice[0], IPv4: intSlice[1], IPv6: intSlice[2]}, nil
}

func newLimitsUpdateTrigger(api ec2API, minInterval, timeout time.Duration, retryCount int) (*trigger.Trigger, error) {
	return trigger.NewTrigger(trigger.Parameters{
		Name:        "ec2-instance-limits-update",
		MinInterval: minInterval,
		TriggerFunc: func(reasons []string) {
			if err := updateFromEC2APIWithRetry(context.TODO(), api, timeout, retryCount); err != nil {
				log.WithError(err).Warning("Failed to update instance limits from EC2 API")
			}

			limits.Lock()
			limits.lastUpdate = time.Now()
			select {
			case limits.triggerDone <- struct{}{}:
			default:
				log.Debug("Skipping trigger done signal as channel is full")
			}
			limits.Unlock()
		},
	})
}

func InitEC2APIUpdateTrigger(api ec2API, triggerMinInterval, ec2APITimeout time.Duration, ec2APIRetryCount int) error {
	limits.Lock()
	limits.triggerMinInterval = triggerMinInterval
	limits.ec2APITimeout = ec2APITimeout
	limits.ec2APIRetryCount = ec2APIRetryCount

	t, err := newLimitsUpdateTrigger(api, triggerMinInterval, ec2APITimeout, ec2APIRetryCount)
	if err != nil {
		log.WithError(err).Fatal("Failed to create EC2 update trigger")
		limits.Unlock()
		return err
	}
	limits.limitsUpdateTrigger = t
	limits.Unlock()

	t.Trigger()
	return nil
}

func updateFromEC2APIWithRetry(ctx context.Context, api ec2API, timeout time.Duration, retryCount int) error {

	return resiliency.Retry(ctx,
		timeout,
		retryCount,
		func(ctx context.Context, retries int) (bool, error) {
			err := UpdateFromEC2API(ctx, api)
			if err != nil {
				log.WithError(err).WithField("retry", retries).Debug("Retrying EC2 API limits update")
				return false, nil
			}
			return true, nil
		},
	)
}

func GetTriggerDone() chan struct{} {
	limits.RLock()
	defer limits.RUnlock()
	return limits.triggerDone
}
