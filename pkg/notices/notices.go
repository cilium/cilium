// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package notices

import (
	"context"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/go-openapi/strfmt"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/time"
)

// Notices manages agent notices.
type Notices struct {
	db  *statedb.DB
	tbl statedb.RWTable[Notice]
}

// All returns the posted notices.
func (n Notices) All() []Notice {
	return statedb.Collect(n.tbl.All(n.db.ReadTxn()))
}

// Post a notice.
func (n Notices) Post(title, message string, timeToLive time.Duration) {
	txn := n.db.WriteTxn(n.tbl)
	n.tbl.Insert(txn, Notice{Title: title, Message: message, PostedAt: time.Now(), TimeToLive: timeToLive})
	txn.Commit()
}

// Retract a posted notice. Does nothing if the notice is not found.
func (n Notices) Retract(title string) {
	txn := n.db.WriteTxn(n.tbl)
	n.tbl.Delete(txn, Notice{Title: title})
	txn.Commit()
}

// Notice to the user to inform of unexpected, but non-fatal circumstances.
//
// Notices can be used to for example inform about use of deprecated options
// or about non-fatal misconfigurations.
type Notice struct {
	// Title of the notice. This should be short and consistent for the same type of
	// notice across agents so duplicate notices can be collapsed.
	Title string `json:"title"`

	// Message to display to the user.
	Message string `json:"message"`

	// PostedAt is the time at which the notice was posted.
	PostedAt time.Time `json:"posted_at"`

	// TimeToLive specifies how long the notice stays alive.
	TimeToLive time.Duration `json:"time_to_live,omitempty"`
}

func (n Notice) TableHeader() []string {
	return []string{
		"Title",
		"Message",
		"Ago",
	}
}

func (n Notice) TableRow() []string {
	return []string{
		n.Title,
		n.Message,
		duration.HumanDuration(time.Since(n.PostedAt)),
	}
}

// ToModel converts the notice into the API model for inclusion into
// the status response.
func (n Notice) ToModel() *models.Notice {
	return &models.Notice{
		Title:    n.Title,
		Message:  n.Message,
		PostedAt: strfmt.DateTime(n.PostedAt),
	}
}

const TableName = "notices"

var (
	titleIndex = statedb.Index[Notice, string]{
		Name: "title",
		FromObject: func(obj Notice) index.KeySet {
			return index.NewKeySet(index.String(obj.Title))
		},
		FromKey: index.String,
		Unique:  true,
	}
	ByTitle = titleIndex.Query
)

func NewNoticeTable(db *statedb.DB) (statedb.RWTable[Notice], error) {
	tbl, err := statedb.NewTable(
		TableName,
		titleIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

const noticeCleanupInterval = 10 * time.Minute

func NewNotices(jg job.Group, db *statedb.DB, tbl statedb.RWTable[Notice]) Notices {
	n := Notices{db, tbl}
	jg.Add(job.Timer(
		"cleanup",
		n.periodicCleanup,
		noticeCleanupInterval,
	))
	return n
}

func (n Notices) periodicCleanup(ctx context.Context) error {
	now := time.Now()
	wtxn := n.db.WriteTxn(n.tbl)
	defer wtxn.Commit()
	for notice := range n.tbl.All(wtxn) {
		if notice.PostedAt.Add(notice.TimeToLive).Before(now) {
			n.tbl.Delete(wtxn, notice)
		}
	}
	return nil
}
