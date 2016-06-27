package server

import (
	"net/http"
	"time"
)

// Logger creates a wrapper for inner and logs all requests made to that particular inner.
func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		log.Debugf(
			"[SERVER] %s\t%s\t%s\t%s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
}
