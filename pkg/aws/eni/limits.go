// Copyright 2019 Authors of Cilium
// Copyright 2017 Lyft, Inc.
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

package eni

import (
	"fmt"
	"strconv"
	"strings"
)

// Limits specifies the ENI relevant instance limits
type Limits struct {
	// Adapters specifies the maximum number of ENIs that can be attached
	// to the instance
	Adapters int

	// IPv4 is the maximum number of IPv4 addresses per ENI
	IPv4 int

	// IPv6 is the maximum number of IPv6 addresses per ENI
	IPv6 int
}

// limit contains limits for adapter count and addresses
// The mappings will be updated from agent configuration at bootstrap time
//
// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html?shortFooter=true#AvailableIpPerENI
var limits = map[string]Limits{
	"a1.medium":     {2, 4, 4},
	"a1.large":      {3, 10, 10},
	"a1.xlarge":     {4, 15, 15},
	"a1.2xlarge":    {4, 15, 15},
	"a1.4xlarge":    {8, 30, 30},
	"c1.medium":     {2, 6, 0},
	"c1.xlarge":     {4, 15, 0},
	"c3.large":      {3, 10, 10},
	"c3.xlarge":     {4, 15, 15},
	"c3.2xlarge":    {4, 15, 15},
	"c3.4xlarge":    {8, 30, 30},
	"c3.8xlarge":    {8, 30, 30},
	"c4.large":      {3, 10, 10},
	"c4.xlarge":     {4, 15, 15},
	"c4.2xlarge":    {4, 15, 15},
	"c4.4xlarge":    {8, 30, 30},
	"c4.8xlarge":    {8, 30, 30},
	"c5.large":      {3, 10, 10},
	"c5.xlarge":     {4, 15, 15},
	"c5.2xlarge":    {4, 15, 15},
	"c5.4xlarge":    {8, 30, 30},
	"c5.9xlarge":    {8, 30, 30},
	"c5.12xlarge":   {8, 30, 30},
	"c5.18xlarge":   {15, 50, 50},
	"c5.24xlarge":   {15, 50, 50},
	"c5.metal":      {15, 50, 50},
	"c5d.large":     {3, 10, 10},
	"c5d.xlarge":    {4, 15, 15},
	"c5d.2xlarge":   {4, 15, 15},
	"c5d.4xlarge":   {8, 30, 30},
	"c5d.9xlarge":   {8, 30, 30},
	"c5d.18xlarge":  {15, 50, 50},
	"c5n.large":     {3, 10, 10},
	"c5n.xlarge":    {4, 15, 15},
	"c5n.2xlarge":   {4, 15, 15},
	"c5n.4xlarge":   {8, 30, 30},
	"c5n.9xlarge":   {8, 30, 30},
	"c5n.18xlarge":  {15, 50, 50},
	"c5n.metal":     {15, 50, 50},
	"cc2.8xlarge":   {8, 30, 0},
	"cr1.8xlarge":   {8, 30, 0},
	"d2.xlarge":     {4, 15, 15},
	"d2.2xlarge":    {4, 15, 15},
	"d2.4xlarge":    {8, 30, 30},
	"d2.8xlarge":    {8, 30, 30},
	"f1.2xlarge":    {4, 15, 15},
	"f1.4xlarge":    {8, 30, 30},
	"f1.16xlarge":   {8, 50, 50},
	"g2.2xlarge":    {4, 15, 0},
	"g2.8xlarge":    {8, 30, 0},
	"g3s.xlarge":    {4, 15, 15},
	"g3.4xlarge":    {8, 30, 30},
	"g3.8xlarge":    {8, 30, 30},
	"g3.16xlarge":   {15, 50, 50},
	"h1.2xlarge":    {4, 15, 15},
	"h1.4xlarge":    {8, 30, 30},
	"h1.8xlarge":    {8, 30, 30},
	"h1.16xlarge":   {15, 50, 50},
	"hs1.8xlarge":   {8, 30, 0},
	"i2.xlarge":     {4, 15, 15},
	"i2.2xlarge":    {4, 15, 15},
	"i2.4xlarge":    {8, 30, 30},
	"i2.8xlarge":    {8, 30, 30},
	"i3.large":      {3, 10, 10},
	"i3.xlarge":     {4, 15, 15},
	"i3.2xlarge":    {4, 15, 15},
	"i3.4xlarge":    {8, 30, 30},
	"i3.8xlarge":    {8, 30, 30},
	"i3.16xlarge":   {15, 50, 50},
	"i3.metal":      {15, 50, 50},
	"i3en.large":    {3, 10, 10},
	"i3en.xlarge":   {4, 15, 15},
	"i3en.2xlarge":  {4, 15, 15},
	"i3en.3xlarge":  {4, 15, 15},
	"i3en.6xlarge":  {8, 30, 30},
	"i3en.12xlarge": {8, 30, 30},
	"i3en.24xlarge": {15, 50, 50},
	"i3en.metal":    {15, 50, 50},
	"m1.small":      {2, 4, 0},
	"m1.medium":     {2, 6, 0},
	"m1.large":      {3, 10, 0},
	"m1.xlarge":     {4, 15, 0},
	"m2.xlarge":     {4, 15, 0},
	"m2.2xlarge":    {4, 30, 0},
	"m2.4xlarge":    {8, 30, 0},
	"m3.medium":     {2, 6, 0},
	"m3.large":      {3, 10, 0},
	"m3.xlarge":     {4, 15, 0},
	"m3.2xlarge":    {4, 30, 0},
	"m4.large":      {2, 10, 10},
	"m4.xlarge":     {4, 15, 15},
	"m4.2xlarge":    {4, 15, 15},
	"m4.4xlarge":    {8, 30, 30},
	"m4.10xlarge":   {8, 30, 30},
	"m4.16xlarge":   {8, 30, 30},
	"m5.large":      {3, 10, 10},
	"m5.xlarge":     {4, 15, 15},
	"m5.2xlarge":    {4, 15, 15},
	"m5.4xlarge":    {8, 30, 30},
	"m5.8xlarge":    {8, 30, 30},
	"m5.12xlarge":   {8, 30, 30},
	"m5.16xlarge":   {15, 50, 50},
	"m5.24xlarge":   {15, 50, 50},
	"m5.metal":      {15, 50, 50},
	"m5a.large":     {3, 10, 10},
	"m5a.xlarge":    {4, 15, 15},
	"m5a.2xlarge":   {4, 15, 15},
	"m5a.4xlarge":   {8, 30, 30},
	"m5a.8xlarge":   {8, 30, 30},
	"m5a.12xlarge":  {8, 30, 30},
	"m5a.16xlarge":  {15, 50, 50},
	"m5a.24xlarge":  {15, 50, 50},
	"m5ad.large":    {3, 10, 10},
	"m5ad.xlarge":   {4, 15, 15},
	"m5ad.2xlarge":  {4, 15, 15},
	"m5ad.4xlarge":  {8, 30, 30},
	"m5ad.12xlarge": {8, 30, 30},
	"m5ad.24xlarge": {15, 50, 50},
	"m5d.large":     {3, 10, 10},
	"m5d.xlarge":    {4, 15, 15},
	"m5d.2xlarge":   {4, 15, 15},
	"m5d.4xlarge":   {8, 30, 30},
	"m5d.8xlarge":   {8, 30, 30},
	"m5d.12xlarge":  {8, 30, 30},
	"m5d.16xlarge":  {15, 50, 50},
	"m5d.24xlarge":  {15, 50, 50},
	"m5d.metal":     {15, 50, 50},
	"p2.xlarge":     {4, 15, 15},
	"p2.8xlarge":    {8, 30, 30},
	"p2.16xlarge":   {8, 30, 30},
	"p3.2xlarge":    {4, 15, 15},
	"p3.8xlarge":    {8, 30, 30},
	"p3.16xlarge":   {8, 30, 30},
	"p3dn.24xlarge": {15, 50, 50},
	"r3.large":      {3, 10, 10},
	"r3.xlarge":     {4, 15, 15},
	"r3.2xlarge":    {4, 15, 15},
	"r3.4xlarge":    {8, 30, 30},
	"r3.8xlarge":    {8, 30, 30},
	"r4.large":      {3, 10, 10},
	"r4.xlarge":     {4, 15, 15},
	"r4.2xlarge":    {4, 15, 15},
	"r4.4xlarge":    {8, 30, 30},
	"r4.8xlarge":    {8, 30, 30},
	"r4.16xlarge":   {15, 50, 50},
	"r5.large":      {3, 10, 10},
	"r5.xlarge":     {4, 15, 15},
	"r5.2xlarge":    {4, 15, 15},
	"r5.4xlarge":    {8, 30, 30},
	"r5.8xlarge":    {8, 30, 30},
	"r5.12xlarge":   {8, 30, 30},
	"r5.16xlarge":   {15, 50, 50},
	"r5.24xlarge":   {15, 50, 50},
	"r5.metal":      {15, 50, 50},
	"r5a.large":     {3, 10, 10},
	"r5a.xlarge":    {4, 15, 15},
	"r5a.2xlarge":   {4, 15, 15},
	"r5a.4xlarge":   {8, 30, 30},
	"r5a.8xlarge":   {8, 30, 30},
	"r5a.12xlarge":  {8, 30, 30},
	"r5a.16xlarge":  {15, 50, 50},
	"r5a.24xlarge":  {15, 50, 50},
	"r5ad.large":    {3, 10, 10},
	"r5ad.xlarge":   {4, 15, 15},
	"r5ad.2xlarge":  {4, 15, 15},
	"r5ad.4xlarge":  {8, 30, 30},
	"r5ad.12xlarge": {8, 30, 30},
	"r5ad.24xlarge": {15, 50, 50},
	"r5d.large":     {3, 10, 10},
	"r5d.xlarge":    {4, 15, 15},
	"r5d.2xlarge":   {4, 15, 15},
	"r5d.4xlarge":   {8, 30, 30},
	"r5d.8xlarge":   {8, 30, 30},
	"r5d.12xlarge":  {8, 30, 30},
	"r5d.16xlarge":  {15, 50, 50},
	"r5d.24xlarge":  {15, 50, 50},
	"r5d.metal":     {15, 50, 50},
	"t1.micro":      {2, 2, 0},
	"t2.nano":       {2, 2, 2},
	"t2.micro":      {2, 2, 2},
	"t2.small":      {3, 4, 4},
	"t2.medium":     {3, 6, 6},
	"t2.large":      {3, 12, 12},
	"t2.xlarge":     {3, 15, 15},
	"t2.2xlarge":    {3, 15, 15},
	"t3.nano":       {2, 2, 2},
	"t3.micro":      {2, 2, 2},
	"t3.small":      {3, 4, 4},
	"t3.medium":     {3, 6, 6},
	"t3.large":      {3, 12, 12},
	"t3.xlarge":     {4, 15, 15},
	"t3.2xlarge":    {4, 15, 15},
	"t3a.nano":      {2, 2, 2},
	"t3a.micro":     {2, 2, 2},
	"t3a.small":     {2, 4, 4},
	"t3a.medium":    {3, 6, 6},
	"t3a.large":     {3, 12, 12},
	"t3a.xlarge":    {4, 15, 15},
	"t3a.2xlarge":   {4, 15, 15},
	"u-6tb1.metal":  {5, 30, 30},
	"u-9tb1.metal":  {5, 30, 30},
	"u-12tb1.metal": {5, 30, 30},
	"x1.16xlarge":   {8, 30, 30},
	"x1.32xlarge":   {8, 30, 30},
	"x1e.xlarge":    {3, 10, 10},
	"x1e.2xlarge":   {4, 15, 15},
	"x1e.4xlarge":   {4, 15, 15},
	"x1e.8xlarge":   {4, 15, 15},
	"x1e.16xlarge":  {8, 30, 30},
	"x1e.32xlarge":  {8, 30, 30},
	"z1d.large":     {3, 10, 10},
	"z1d.xlarge":    {4, 15, 15},
	"z1d.2xlarge":   {4, 15, 15},
	"z1d.3xlarge":   {8, 30, 30},
	"z1d.6xlarge":   {8, 30, 30},
	"z1d.12xlarge":  {15, 50, 50},
	"z1d.metal":     {15, 50, 50},
}

// GetLimits returns the instance limits of a particular instance type
func GetLimits(instanceType string) (limit Limits, ok bool) {
	limit, ok = limits[instanceType]
	return
}

// UpdateLimitsFromUserDefinedMappings updates limits from the given map
func UpdateLimitsFromUserDefinedMappings(m map[string]string) (err error) {
	for instanceType, limitString := range m {
		limit, err := parseLimitString(limitString)
		if err != nil {
			return err
		}
		// Add or overwrite limits
		limits[instanceType] = limit
	}
	return nil
}

// parseLimitString returns the Limits struct parsed from config string
func parseLimitString(limitString string) (limit Limits, err error) {
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
	return Limits{intSlice[0], intSlice[1], intSlice[2]}, nil
}
