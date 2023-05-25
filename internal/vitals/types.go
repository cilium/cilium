// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vitals

const (
	ScoreOK Score = iota
	ScoreDown
	ScoreDegraded
)

const (
	Low HealthScore = iota
	Medium
	High
)

const (
	ok index = iota
	down
	degraded
)

type (
	index int
	Score int

	// HealthScore tracks health score.
	HealthScore int
)
