// Copyright 2019-2020 Authors of Cilium
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

package limits

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	ec2shim "github.com/cilium/cilium/pkg/aws/ec2"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// limit contains limits for adapter count and addresses. The mappings will be
// updated from agent configuration at bootstrap time.
//
// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html?shortFooter=true#AvailableIpPerENI
var limits = struct {
	lock.RWMutex

	m map[string]ipamTypes.Limits
}{
	m: map[string]ipamTypes.Limits{
		"a1.medium":     {Adapters: 2, IPv4: 4, IPv6: 4},
		"a1.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"a1.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"a1.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"a1.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"a1.metal":      {Adapters: 8, IPv4: 30, IPv6: 30},
		"c1.medium":     {Adapters: 2, IPv4: 6, IPv6: 0},
		"c1.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 0},
		"c3.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"c3.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"c3.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"c3.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"c3.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"c4.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"c4.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"c4.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"c4.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"c4.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"c5.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"c5.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"c5.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"c5.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"c5.9xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"c5.12xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"c5.18xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"c5.24xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"c5.metal":      {Adapters: 15, IPv4: 50, IPv6: 50},
		"c5d.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"c5d.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"c5d.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"c5d.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"c5d.9xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"c5d.18xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"c5d.metal":     {Adapters: 15, IPv4: 50, IPv6: 50},
		"c5n.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"c5n.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"c5n.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"c5n.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"c5n.9xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"c5n.18xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"c5n.metal":     {Adapters: 15, IPv4: 50, IPv6: 50},
		"cc2.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 0},
		"cr1.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 0},
		"d2.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"d2.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"d2.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"d2.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"f1.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"f1.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"f1.16xlarge":   {Adapters: 8, IPv4: 50, IPv6: 50},
		"g2.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 0},
		"g2.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 0},
		"g3s.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"g3.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"g3.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"g3.16xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"g4dn.xlarge":   {Adapters: 3, IPv4: 10, IPv6: 10},
		"g4dn.2xlarge":  {Adapters: 3, IPv4: 10, IPv6: 10},
		"g4dn.4xlarge":  {Adapters: 3, IPv4: 10, IPv6: 10},
		"g4dn.8xlarge":  {Adapters: 4, IPv4: 15, IPv6: 15},
		"g4dn.12xlarge": {Adapters: 8, IPv4: 30, IPv6: 30},
		"g4dn.16xlarge": {Adapters: 4, IPv4: 15, IPv6: 15},
		"h1.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"h1.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"h1.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"h1.16xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"hs1.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 0},
		"i2.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"i2.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"i2.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"i2.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"i3.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"i3.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"i3.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"i3.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"i3.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"i3.16xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"i3.metal":      {Adapters: 15, IPv4: 50, IPv6: 50},
		"i3en.large":    {Adapters: 3, IPv4: 10, IPv6: 10},
		"i3en.xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"i3en.2xlarge":  {Adapters: 4, IPv4: 15, IPv6: 15},
		"i3en.3xlarge":  {Adapters: 4, IPv4: 15, IPv6: 15},
		"i3en.6xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"i3en.12xlarge": {Adapters: 8, IPv4: 30, IPv6: 30},
		"i3en.24xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"i3en.metal":    {Adapters: 15, IPv4: 50, IPv6: 50},
		"inf1.xlarge":   {Adapters: 4, IPv4: 10, IPv6: 10},
		"inf1.2xlarge":  {Adapters: 4, IPv4: 10, IPv6: 10},
		"inf1.6xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"inf1.24xlarge": {Adapters: 15, IPv4: 30, IPv6: 30},
		"m1.small":      {Adapters: 2, IPv4: 4, IPv6: 0},
		"m1.medium":     {Adapters: 2, IPv4: 6, IPv6: 0},
		"m1.large":      {Adapters: 3, IPv4: 10, IPv6: 0},
		"m1.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 0},
		"m2.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 0},
		"m2.2xlarge":    {Adapters: 4, IPv4: 30, IPv6: 0},
		"m2.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 0},
		"m3.medium":     {Adapters: 2, IPv4: 6, IPv6: 0},
		"m3.large":      {Adapters: 3, IPv4: 10, IPv6: 0},
		"m3.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 0},
		"m3.2xlarge":    {Adapters: 4, IPv4: 30, IPv6: 0},
		"m4.large":      {Adapters: 2, IPv4: 10, IPv6: 10},
		"m4.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"m4.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"m4.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"m4.10xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m4.16xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"m5.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5.12xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5.16xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5.24xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5.metal":      {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5a.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"m5a.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5a.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5a.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5a.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5a.12xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5a.16xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5a.24xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5ad.large":    {Adapters: 3, IPv4: 10, IPv6: 10},
		"m5ad.xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5ad.2xlarge":  {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5ad.4xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5ad.8xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5ad.12xlarge": {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5ad.16xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5ad.24xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5d.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"m5d.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5d.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5d.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5d.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5d.12xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5d.16xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5d.24xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5d.metal":     {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5dn.large":    {Adapters: 3, IPv4: 10, IPv6: 10},
		"m5dn.xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5dn.2xlarge":  {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5dn.4xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5dn.8xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5dn.12xlarge": {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5dn.16xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5dn.24xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5n.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"m5n.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5n.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"m5n.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5n.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5n.12xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"m5n.16xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"m5n.24xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"m6g.medium":    {Adapters: 2, IPv4: 4, IPv6: 4},
		"m6g.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"m6g.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"m6g.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"m6g.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m6g.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"m6g.12xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"m6g.16xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"m6g.metal":     {Adapters: 15, IPv4: 50, IPv6: 50},
		"p2.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"p2.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"p2.16xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"p3.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"p3.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"p3.16xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"p3dn.24xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"r3.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"r3.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"r3.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"r3.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"r3.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"r4.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"r4.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"r4.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"r4.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"r4.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"r4.16xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5.large":      {Adapters: 3, IPv4: 10, IPv6: 10},
		"r5.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5.4xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5.8xlarge":    {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5.12xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5.16xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5.24xlarge":   {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5.metal":      {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5a.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"r5a.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5a.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5a.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5a.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5a.12xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5a.16xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5a.24xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5ad.large":    {Adapters: 3, IPv4: 10, IPv6: 10},
		"r5ad.xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5ad.2xlarge":  {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5ad.4xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5ad.8xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5ad.12xlarge": {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5ad.16xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5ad.24xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5d.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"r5d.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5d.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5d.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5d.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5d.12xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5d.16xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5d.24xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5d.metal":     {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5dn.large":    {Adapters: 3, IPv4: 10, IPv6: 10},
		"r5dn.xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5dn.2xlarge":  {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5dn.4xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5dn.8xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5dn.12xlarge": {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5dn.16xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5dn.24xlarge": {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5n.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"r5n.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5n.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"r5n.4xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5n.8xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5n.12xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"r5n.16xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"r5n.24xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"t1.micro":      {Adapters: 2, IPv4: 2, IPv6: 0},
		"t2.nano":       {Adapters: 2, IPv4: 2, IPv6: 2},
		"t2.micro":      {Adapters: 2, IPv4: 2, IPv6: 2},
		"t2.small":      {Adapters: 3, IPv4: 4, IPv6: 4},
		"t2.medium":     {Adapters: 3, IPv4: 6, IPv6: 6},
		"t2.large":      {Adapters: 3, IPv4: 12, IPv6: 12},
		"t2.xlarge":     {Adapters: 3, IPv4: 15, IPv6: 15},
		"t2.2xlarge":    {Adapters: 3, IPv4: 15, IPv6: 15},
		"t3.nano":       {Adapters: 2, IPv4: 2, IPv6: 2},
		"t3.micro":      {Adapters: 2, IPv4: 2, IPv6: 2},
		"t3.small":      {Adapters: 3, IPv4: 4, IPv6: 4},
		"t3.medium":     {Adapters: 3, IPv4: 6, IPv6: 6},
		"t3.large":      {Adapters: 3, IPv4: 12, IPv6: 12},
		"t3.xlarge":     {Adapters: 4, IPv4: 15, IPv6: 15},
		"t3.2xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"t3a.nano":      {Adapters: 2, IPv4: 2, IPv6: 2},
		"t3a.micro":     {Adapters: 2, IPv4: 2, IPv6: 2},
		"t3a.small":     {Adapters: 2, IPv4: 4, IPv6: 4},
		"t3a.medium":    {Adapters: 3, IPv4: 6, IPv6: 6},
		"t3a.large":     {Adapters: 3, IPv4: 12, IPv6: 12},
		"t3a.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"t3a.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"u-6tb1.metal":  {Adapters: 5, IPv4: 30, IPv6: 30},
		"u-9tb1.metal":  {Adapters: 5, IPv4: 30, IPv6: 30},
		"u-12tb1.metal": {Adapters: 5, IPv4: 30, IPv6: 30},
		"u-18tb1.metal": {Adapters: 15, IPv4: 50, IPv6: 50},
		"u-24tb1.metal": {Adapters: 15, IPv4: 50, IPv6: 50},
		"x1.16xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"x1.32xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"x1e.xlarge":    {Adapters: 3, IPv4: 10, IPv6: 10},
		"x1e.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"x1e.4xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"x1e.8xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"x1e.16xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"x1e.32xlarge":  {Adapters: 8, IPv4: 30, IPv6: 30},
		"z1d.large":     {Adapters: 3, IPv4: 10, IPv6: 10},
		"z1d.xlarge":    {Adapters: 4, IPv4: 15, IPv6: 15},
		"z1d.2xlarge":   {Adapters: 4, IPv4: 15, IPv6: 15},
		"z1d.3xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"z1d.6xlarge":   {Adapters: 8, IPv4: 30, IPv6: 30},
		"z1d.12xlarge":  {Adapters: 15, IPv4: 50, IPv6: 50},
		"z1d.metal":     {Adapters: 15, IPv4: 50, IPv6: 50},
	},
}

// Get returns the instance limits of a particular instance type.
func Get(instanceType string) (limit ipamTypes.Limits, ok bool) {
	limits.RLock()
	limit, ok = limits.m[instanceType]
	limits.RUnlock()
	return
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

// UpdateFromEC2API updates limits from the EC2 API via calling
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceTypes.html.
func UpdateFromEC2API(ctx context.Context, ec2Client *ec2shim.Client) error {
	instanceTypeInfos, err := ec2Client.GetInstanceTypes(ctx)
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

		limits.m[instanceType] = ipamTypes.Limits{
			Adapters: int(adapterLimit),
			IPv4:     int(ipv4PerAdapter),
			IPv6:     int(ipv6PerAdapter),
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
