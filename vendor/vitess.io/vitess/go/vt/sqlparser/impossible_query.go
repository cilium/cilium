package sqlparser

// FormatImpossibleQuery creates an impossible query in a TrackedBuffer.
// An impossible query is a modified version of a query where all selects have where clauses that are
// impossible for mysql to resolve. This is used in the vtgate and vttablet:
//
// - In the vtgate it's used for joins: if the first query returns no result, then vtgate uses the impossible
// query just to fetch field info from vttablet
// - In the vttablet, it's just an optimization: the field info is fetched once form MySQL, cached and reused
// for subsequent queries
func FormatImpossibleQuery(buf *TrackedBuffer, node SQLNode) {
	switch node := node.(type) {
	case *Select:
		buf.Myprintf("select %v from %v where 1 != 1", node.SelectExprs, node.From)
		if node.GroupBy != nil {
			node.GroupBy.Format(buf)
		}
	case *Union:
		buf.Myprintf("%v %s %v", node.Left, node.Type, node.Right)
	default:
		node.Format(buf)
	}
}
