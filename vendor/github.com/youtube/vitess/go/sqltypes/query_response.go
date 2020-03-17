package sqltypes

// QueryResponse represents a query response for ExecuteBatch.
type QueryResponse struct {
	QueryResult *Result
	QueryError  error
}
