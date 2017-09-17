package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedocMiddleware(t *testing.T) {
	redoc := Redoc(RedocOpts{}, nil)

	req, _ := http.NewRequest("GET", "/docs", nil)
	recorder := httptest.NewRecorder()
	redoc.ServeHTTP(recorder, req)
	assert.Equal(t, 200, recorder.Code)
	assert.Equal(t, "text/html; charset=utf-8", recorder.Header().Get("Content-Type"))
	assert.Contains(t, recorder.Body.String(), "<title>API documentation</title>")
	assert.Contains(t, recorder.Body.String(), "<redoc spec-url='/swagger.json'></redoc>")
	assert.Contains(t, recorder.Body.String(), redocLatest)
}
