package sqltypes

import querypb "github.com/youtube/vitess/go/vt/proto/query"

// EventTokenMinimum returns an event token that is guaranteed to
// happen before both provided EventToken objects. Note it doesn't
// parse the position, but rather only uses the timestamp. This is
// meant to be used for EventToken objects coming from different
// source shard.
func EventTokenMinimum(ev1, ev2 *querypb.EventToken) *querypb.EventToken {
	if ev1 == nil || ev2 == nil {
		// One or the other is not set, we can't do anything.
		return nil
	}

	if ev1.Timestamp < ev2.Timestamp {
		return &querypb.EventToken{
			Timestamp: ev1.Timestamp,
		}
	}
	return &querypb.EventToken{
		Timestamp: ev2.Timestamp,
	}
}
