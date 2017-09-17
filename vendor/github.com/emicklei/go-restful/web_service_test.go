package restful

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	pathGetFriends = "/get/{userId}/friends"
)

func TestParameter(t *testing.T) {
	p := &Parameter{&ParameterData{Name: "name", Description: "desc"}}
	p.AllowMultiple(true)
	p.DataType("int")
	p.Required(true)
	values := map[string]string{"a": "b"}
	p.AllowableValues(values)
	p.bePath()

	ws := new(WebService)
	ws.Param(p)
	if ws.pathParameters[0].Data().Name != "name" {
		t.Error("path parameter (or name) invalid")
	}
}
func TestWebService_CanCreateParameterKinds(t *testing.T) {
	ws := new(WebService)
	if ws.BodyParameter("b", "b").Kind() != BodyParameterKind {
		t.Error("body parameter expected")
	}
	if ws.PathParameter("p", "p").Kind() != PathParameterKind {
		t.Error("path parameter expected")
	}
	if ws.QueryParameter("q", "q").Kind() != QueryParameterKind {
		t.Error("query parameter expected")
	}
}

func TestCapturePanic(t *testing.T) {
	tearDown()
	Add(newPanicingService())
	httpRequest, _ := http.NewRequest("GET", "http://here.com/fire", nil)
	httpRequest.Header.Set("Accept", "*/*")
	httpWriter := httptest.NewRecorder()
	// override the default here
	DefaultContainer.DoNotRecover(false)
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 500 != httpWriter.Code {
		t.Error("500 expected on fire")
	}
}

func TestCapturePanicWithEncoded(t *testing.T) {
	tearDown()
	Add(newPanicingService())
	DefaultContainer.EnableContentEncoding(true)
	httpRequest, _ := http.NewRequest("GET", "http://here.com/fire", nil)
	httpRequest.Header.Set("Accept", "*/*")
	httpRequest.Header.Set("Accept-Encoding", "gzip")
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 500 != httpWriter.Code {
		t.Error("500 expected on fire, got", httpWriter.Code)
	}
}

func TestNotFound(t *testing.T) {
	tearDown()
	httpRequest, _ := http.NewRequest("GET", "http://here.com/missing", nil)
	httpRequest.Header.Set("Accept", "*/*")
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 404 != httpWriter.Code {
		t.Error("404 expected on missing")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	tearDown()
	Add(newGetOnlyService())
	httpRequest, _ := http.NewRequest("POST", "http://here.com/get", nil)
	httpRequest.Header.Set("Accept", "*/*")
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 405 != httpWriter.Code {
		t.Error("405 expected method not allowed")
	}
}

func TestSelectedRoutePath_Issue100(t *testing.T) {
	tearDown()
	Add(newSelectedRouteTestingService())
	httpRequest, _ := http.NewRequest("GET", "http://here.com/get/232452/friends", nil)
	httpRequest.Header.Set("Accept", "*/*")
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if http.StatusOK != httpWriter.Code {
		t.Error(http.StatusOK, "expected,", httpWriter.Code, "received.")
	}
}

func TestContentType415_Issue170(t *testing.T) {
	tearDown()
	Add(newGetOnlyJsonOnlyService())
	httpRequest, _ := http.NewRequest("GET", "http://here.com/get", nil)
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 200 != httpWriter.Code {
		t.Errorf("Expected 200, got %d", httpWriter.Code)
	}
}

func TestNoContentTypePOST(t *testing.T) {
	tearDown()
	Add(newPostNoConsumesService())
	httpRequest, _ := http.NewRequest("POST", "http://here.com/post", nil)
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 204 != httpWriter.Code {
		t.Errorf("Expected 204, got %d", httpWriter.Code)
	}
}

func TestContentType415_POST_Issue170(t *testing.T) {
	tearDown()
	Add(newPostOnlyJsonOnlyService())
	httpRequest, _ := http.NewRequest("POST", "http://here.com/post", nil)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 200 != httpWriter.Code {
		t.Errorf("Expected 200, got %d", httpWriter.Code)
	}
}

// go test -v -test.run TestContentType406PlainJson ...restful
func TestContentType406PlainJson(t *testing.T) {
	tearDown()
	TraceLogger(testLogger{t})
	Add(newGetPlainTextOrJsonService())
	httpRequest, _ := http.NewRequest("GET", "http://here.com/get", nil)
	httpRequest.Header.Set("Accept", "text/plain")
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if got, want := httpWriter.Code, 200; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRemoveRoute(t *testing.T) {
	tearDown()
	TraceLogger(testLogger{t})
	ws := newGetPlainTextOrJsonService()
	Add(ws)
	httpRequest, _ := http.NewRequest("GET", "http://here.com/get", nil)
	httpRequest.Header.Set("Accept", "text/plain")
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if got, want := httpWriter.Code, 200; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	// dynamic apis are disabled, should error and do nothing
	if err := ws.RemoveRoute("/get", "GET"); err == nil {
		t.Error("unexpected non-error")
	}

	httpWriter = httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if got, want := httpWriter.Code, 200; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	ws.SetDynamicRoutes(true)
	if err := ws.RemoveRoute("/get", "GET"); err != nil {
		t.Errorf("unexpected error %v", err)
	}

	httpWriter = httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if got, want := httpWriter.Code, 404; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
func TestRemoveLastRoute(t *testing.T) {
	tearDown()
	TraceLogger(testLogger{t})
	ws := newGetPlainTextOrJsonServiceMultiRoute()
	Add(ws)
	httpRequest, _ := http.NewRequest("GET", "http://here.com/get", nil)
	httpRequest.Header.Set("Accept", "text/plain")
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if got, want := httpWriter.Code, 200; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	// dynamic apis are disabled, should error and do nothing
	if err := ws.RemoveRoute("/get", "GET"); err == nil {
		t.Error("unexpected non-error")
	}

	httpWriter = httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if got, want := httpWriter.Code, 200; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	ws.SetDynamicRoutes(true)
	if err := ws.RemoveRoute("/get", "GET"); err != nil {
		t.Errorf("unexpected error %v", err)
	}

	httpWriter = httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if got, want := httpWriter.Code, 404; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// go test -v -test.run TestContentTypeOctet_Issue170 ...restful
func TestContentTypeOctet_Issue170(t *testing.T) {
	tearDown()
	Add(newGetConsumingOctetStreamService())
	// with content-type
	httpRequest, _ := http.NewRequest("GET", "http://here.com/get", nil)
	httpRequest.Header.Set("Content-Type", MIME_OCTET)
	httpWriter := httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 200 != httpWriter.Code {
		t.Errorf("Expected 200, got %d", httpWriter.Code)
	}
	// without content-type
	httpRequest, _ = http.NewRequest("GET", "http://here.com/get", nil)
	httpWriter = httptest.NewRecorder()
	DefaultContainer.dispatch(httpWriter, httpRequest)
	if 200 != httpWriter.Code {
		t.Errorf("Expected 200, got %d", httpWriter.Code)
	}
}

type exampleBody struct{}

func TestParameterDataTypeDefaults(t *testing.T) {
	tearDown()
	ws := new(WebService)
	route := ws.POST("/post").Reads(&exampleBody{})
	if route.parameters[0].data.DataType != "*restful.exampleBody" {
		t.Errorf("body parameter incorrect name: %#v", route.parameters[0].data)
	}
}

func TestParameterDataTypeCustomization(t *testing.T) {
	tearDown()
	ws := new(WebService)
	ws.TypeNameHandler(func(sample interface{}) string {
		return "my.custom.type.name"
	})
	route := ws.POST("/post").Reads(&exampleBody{})
	if route.parameters[0].data.DataType != "my.custom.type.name" {
		t.Errorf("body parameter incorrect name: %#v", route.parameters[0].data)
	}
}

func newPanicingService() *WebService {
	ws := new(WebService).Path("")
	ws.Route(ws.GET("/fire").To(doPanic))
	return ws
}

func newGetOnlyService() *WebService {
	ws := new(WebService).Path("")
	ws.Route(ws.GET("/get").To(doPanic))
	return ws
}

func newPostOnlyJsonOnlyService() *WebService {
	ws := new(WebService).Path("")
	ws.Consumes("application/json")
	ws.Route(ws.POST("/post").To(doNothing))
	return ws
}

func newGetOnlyJsonOnlyService() *WebService {
	ws := new(WebService).Path("")
	ws.Consumes("application/json")
	ws.Route(ws.GET("/get").To(doNothing))
	return ws
}

func newGetPlainTextOrJsonService() *WebService {
	ws := new(WebService).Path("")
	ws.Produces("text/plain", "application/json")
	ws.Route(ws.GET("/get").To(doNothing))
	return ws
}

func newGetPlainTextOrJsonServiceMultiRoute() *WebService {
	ws := new(WebService).Path("")
	ws.Produces("text/plain", "application/json")
	ws.Route(ws.GET("/get").To(doNothing))
	ws.Route(ws.GET("/status").To(doNothing))
	return ws
}

func newGetConsumingOctetStreamService() *WebService {
	ws := new(WebService).Path("")
	ws.Consumes("application/octet-stream")
	ws.Route(ws.GET("/get").To(doNothing))
	return ws
}

func newPostNoConsumesService() *WebService {
	ws := new(WebService).Path("")
	ws.Route(ws.POST("/post").To(return204))
	return ws
}

func newSelectedRouteTestingService() *WebService {
	ws := new(WebService).Path("")
	ws.Route(ws.GET(pathGetFriends).To(selectedRouteChecker))
	return ws
}

func selectedRouteChecker(req *Request, resp *Response) {
	if req.SelectedRoutePath() != pathGetFriends {
		resp.InternalServerError()
	}
}

func doPanic(req *Request, resp *Response) {
	println("lightning...")
	panic("fire")
}

func doNothing(req *Request, resp *Response) {
}

func return204(req *Request, resp *Response) {
	resp.WriteHeader(204)
}
