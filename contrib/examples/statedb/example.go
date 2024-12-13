package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

// Example is our object that we want to index and store in a table.
type Example struct {
	ID        uint64
	CreatedAt time.Time
}

// TableHeader defines how cilium-dbg displays the header
func (e *Example) TableHeader() []string {
	return []string{
		"ID",
		"CreatedAt",
	}
}

// TableRow defines how cilium-dbg displays a row
func (e *Example) TableRow() []string {
	return []string{
		strconv.FormatUint(e.ID, 10),
		e.CreatedAt.String(),
	}
}

// TableName is a constant for the table name. This is used in cilium-dbg
// to refer to this table.
const TableName = "examples"

var (
	// idIndex defines the primary index for the Example object.
	idIndex = statedb.Index[Example, uint64]{
		Name: "id",
		FromObject: func(e Example) index.KeySet {
			return index.NewKeySet(index.Uint64(e.ID))
		},
		FromKey:    index.Uint64,
		FromString: index.Uint64String,
		Unique:     true,
	}
	// ByID exports the query function for the id index. It's a convention
	// for providing a short readable short-hand for creating queries.
	// ("query" is essentially just the index name + the key created with
	//  the "FromKey" method defined above).
	ByID = idIndex.Query
)

// NewExampleTable creates the table and registers it.
func NewExampleTable(db *statedb.DB) (statedb.RWTable[Example], error) {
	tbl, err := statedb.NewTable(
		TableName,
		idIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

// Cell provides the Table[Example] and registers a controller to populate
// the table.
var Cell = cell.Module(
	"example",
	"Examples",

	// Provide RWTable[Example] privately
	cell.ProvidePrivate(NewExampleTable),

	// Provide Table[Example] publicly
	cell.Provide(statedb.RWTable[Example].ToTable),

	// Register a controller that manages the contents of the
	// table.
	cell.Invoke(registerExampleController),
)

type exampleController struct {
	db       *statedb.DB
	examples statedb.RWTable[Example]
}

// loop is a simple control-loop that once a second inserts an example object
// with an increasing [ID]. When 5 objects are reached it deletes everything
// and starts over.
func (e *exampleController) loop(ctx context.Context, health cell.Health) error {
	id := uint64(0)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	health.OK("Starting")
	for {
		var tickTime time.Time
		select {
		case tickTime = <-tick.C:
		case <-ctx.Done():
			return nil
		}
		wtxn := e.db.WriteTxn(e.examples)
		id++
		if id <= 5 {
			e.examples.Insert(wtxn, Example{ID: id, CreatedAt: tickTime})
		} else {
			e.examples.DeleteAll(wtxn)
			id = 0
		}
		wtxn.Commit()

		// Report the health of the job. This can be inspected with
		// "cilium-dbg status --all-health" or with "cilium-dbg shell -- db/show health".
		health.OK(fmt.Sprintf("%d examples inserted", id))
	}
}

func registerExampleController(jg job.Group, db *statedb.DB, examples statedb.RWTable[Example]) {
	// Construct the controller and add the loop() method as a one-shot background
	// job to the module's job group.
	// When the controller doesn't have any useful API to outside we can use this
	// pattern instead of "Provide(NewController)" to keep things internal.
	ctrl := &exampleController{db, examples}
	jg.Add(job.OneShot(
		"loop",
		ctrl.loop,
	))
}
