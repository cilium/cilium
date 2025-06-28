// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

type options uint8

const (
	rootOnlyWatchOpt = options(1 << 1)
	noCacheOpt       = options(1 << 2)
)

func (o *options) setRootOnlyWatch() {
	*o |= rootOnlyWatchOpt
}

func (o *options) setNoCache() {
	*o |= noCacheOpt

}
func (o options) rootOnlyWatch() bool {
	return o&rootOnlyWatchOpt != 0
}

func (o options) noCache() bool {
	return o&noCacheOpt != 0
}
