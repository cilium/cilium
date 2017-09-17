// This implements a very basic Swift server
// Everything is stored in memory
//
// This comes from the https://github.com/mitchellh/goamz
// and was adapted for Swift
//
package swifttest

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncw/swift"
)

const (
	DEBUG        = false
	TEST_ACCOUNT = "swifttest"
)

type SwiftServer struct {
	t        *testing.T
	reqId    int
	mu       sync.Mutex
	Listener net.Listener
	AuthURL  string
	URL      string
	Accounts map[string]*account
	Sessions map[string]*session
}

// The Folder type represents a container stored in an account
type Folder struct {
	Count int    `json:"count"`
	Bytes int    `json:"bytes"`
	Name  string `json:"name"`
}

// The Key type represents an item stored in an container.
type Key struct {
	Key          string `json:"name"`
	LastModified string `json:"last_modified"`
	Size         int64  `json:"bytes"`
	// ETag gives the hex-encoded MD5 sum of the contents,
	// surrounded with double-quotes.
	ETag        string `json:"hash"`
	ContentType string `json:"content_type"`
	// Owner        Owner
}

type Subdir struct {
	Subdir string `json:"subdir"`
}

type swiftError struct {
	statusCode int
	Code       string
	Message    string
}

type action struct {
	srv   *SwiftServer
	w     http.ResponseWriter
	req   *http.Request
	reqId string
	user  *account
}

type session struct {
	username string
}

type metadata struct {
	meta http.Header // metadata to return with requests.
}

type account struct {
	swift.Account
	metadata
	password   string
	Containers map[string]*container
}

type object struct {
	metadata
	name         string
	mtime        time.Time
	checksum     []byte // also held as ETag in meta.
	data         []byte
	content_type string
}

type container struct {
	metadata
	name    string
	ctime   time.Time
	objects map[string]*object
	bytes   int
}

// A resource encapsulates the subject of an HTTP request.
// The resource referred to may or may not exist
// when the request is made.
type resource interface {
	put(a *action) interface{}
	get(a *action) interface{}
	post(a *action) interface{}
	delete(a *action) interface{}
	copy(a *action) interface{}
}

type objectResource struct {
	name      string
	version   string
	container *container // always non-nil.
	object    *object    // may be nil.
}

type containerResource struct {
	name      string
	container *container // non-nil if the container already exists.
}

var responseParams = map[string]bool{
	"content-type":        true,
	"content-language":    true,
	"expires":             true,
	"cache-control":       true,
	"content-disposition": true,
	"content-encoding":    true,
}

func fatalf(code int, codeStr string, errf string, a ...interface{}) {
	panic(&swiftError{
		statusCode: code,
		Code:       codeStr,
		Message:    fmt.Sprintf(errf, a...),
	})
}

func (m metadata) setMetadata(a *action, resource string) {
	for key, values := range a.req.Header {
		key = http.CanonicalHeaderKey(key)
		if metaHeaders[key] || strings.HasPrefix(key, "X-"+strings.Title(resource)+"-Meta-") {
			if values[0] != "" || resource == "object" {
				m.meta[key] = values
			} else {
				m.meta.Del(key)
			}
		}
	}
}

func (m metadata) getMetadata(a *action) {
	h := a.w.Header()
	for name, d := range m.meta {
		h[name] = d
	}
}

func (c container) list(delimiter string, marker string, prefix string, parent string) (resp []interface{}) {
	var tmp orderedObjects

	// first get all matching objects and arrange them in alphabetical order.
	for _, obj := range c.objects {
		if strings.HasPrefix(obj.name, prefix) {
			tmp = append(tmp, obj)
		}
	}
	sort.Sort(tmp)

	var prefixes []string
	for _, obj := range tmp {
		if !strings.HasPrefix(obj.name, prefix) {
			continue
		}

		isPrefix := false
		name := obj.name
		if parent != "" {
			if path.Dir(obj.name) != path.Clean(parent) {
				continue
			}
		} else if delimiter != "" {
			if i := strings.Index(obj.name[len(prefix):], delimiter); i >= 0 {
				name = obj.name[:len(prefix)+i+len(delimiter)]
				if prefixes != nil && prefixes[len(prefixes)-1] == name {
					continue
				}
				isPrefix = true
			}
		}

		if name <= marker {
			continue
		}

		if isPrefix {
			prefixes = append(prefixes, name)

			resp = append(resp, Subdir{
				Subdir: name,
			})
		} else {
			resp = append(resp, obj)
		}
	}

	return
}

// GET on a container lists the objects in the container.
func (r containerResource) get(a *action) interface{} {
	if r.container == nil {
		fatalf(404, "NoSuchContainer", "The specified container does not exist")
	}

	delimiter := a.req.Form.Get("delimiter")
	marker := a.req.Form.Get("marker")
	prefix := a.req.Form.Get("prefix")
	format := a.req.URL.Query().Get("format")
	parent := a.req.Form.Get("path")

	a.w.Header().Set("X-Container-Bytes-Used", strconv.Itoa(r.container.bytes))
	a.w.Header().Set("X-Container-Object-Count", strconv.Itoa(len(r.container.objects)))
	r.container.getMetadata(a)

	if a.req.Method == "HEAD" {
		return nil
	}

	objects := r.container.list(delimiter, marker, prefix, parent)

	if format == "json" {
		a.w.Header().Set("Content-Type", "application/json")
		var resp []interface{}
		for _, item := range objects {
			if obj, ok := item.(*object); ok {
				resp = append(resp, obj.Key())
			} else {
				resp = append(resp, item)
			}
		}
		return resp
	} else {
		for _, item := range objects {
			if obj, ok := item.(*object); ok {
				a.w.Write([]byte(obj.name + "\n"))
			} else if subdir, ok := item.(Subdir); ok {
				a.w.Write([]byte(subdir.Subdir + "\n"))
			}
		}
		return nil
	}
}

// orderedContainers holds a slice of containers that can be sorted
// by name.
type orderedContainers []*container

func (s orderedContainers) Len() int {
	return len(s)
}
func (s orderedContainers) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s orderedContainers) Less(i, j int) bool {
	return s[i].name < s[j].name
}

func (r containerResource) delete(a *action) interface{} {
	b := r.container
	if b == nil {
		fatalf(404, "NoSuchContainer", "The specified container does not exist")
	}
	if len(b.objects) > 0 {
		fatalf(409, "Conflict", "The container you tried to delete is not empty")
	}
	delete(a.user.Containers, b.name)
	a.user.Account.Containers--
	return nil
}

func (r containerResource) put(a *action) interface{} {
	if a.req.URL.Query().Get("extract-archive") != "" {
		fatalf(403, "Operation forbidden", "Bulk upload is not supported")
	}

	if r.container == nil {
		if !validContainerName(r.name) {
			fatalf(400, "InvalidContainerName", "The specified container is not valid")
		}
		r.container = &container{
			name:    r.name,
			objects: make(map[string]*object),
			metadata: metadata{
				meta: make(http.Header),
			},
		}
		r.container.setMetadata(a, "container")
		a.user.Containers[r.name] = r.container
		a.user.Account.Containers++
	}

	return nil
}

func (r containerResource) post(a *action) interface{} {
	if r.container == nil {
		fatalf(400, "Method", "The resource could not be found.")
	} else {
		r.container.setMetadata(a, "container")
		a.w.WriteHeader(201)
		jsonMarshal(a.w, Folder{
			Count: len(r.container.objects),
			Bytes: r.container.bytes,
			Name:  r.container.name,
		})
	}
	return nil
}

func (containerResource) copy(a *action) interface{} { return notAllowed() }

// validContainerName returns whether name is a valid bucket name.
// Here are the rules, from:
// http://docs.openstack.org/api/openstack-object-storage/1.0/content/ch_object-storage-dev-api-storage.html
//
// Container names cannot exceed 256 bytes and cannot contain the / character.
//
func validContainerName(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	for _, r := range name {
		switch {
		case r == '/':
			return false
		default:
		}
	}
	return true
}

// orderedObjects holds a slice of objects that can be sorted
// by name.
type orderedObjects []*object

func (s orderedObjects) Len() int {
	return len(s)
}
func (s orderedObjects) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s orderedObjects) Less(i, j int) bool {
	return s[i].name < s[j].name
}

func (obj *object) Key() Key {
	return Key{
		Key:          obj.name,
		LastModified: obj.mtime.Format("2006-01-02T15:04:05"),
		Size:         int64(len(obj.data)),
		ETag:         fmt.Sprintf("%x", obj.checksum),
		ContentType:  obj.content_type,
	}
}

var metaHeaders = map[string]bool{
	"Content-Type":        true,
	"Content-Encoding":    true,
	"Content-Disposition": true,
	"X-Object-Manifest":   true,
}

var rangeRegexp = regexp.MustCompile("(bytes=)?([0-9]*)-([0-9]*)")

// GET on an object gets the contents of the object.
func (objr objectResource) get(a *action) interface{} {
	var (
		etag   []byte
		reader io.Reader
		start  int
		end    int = -1
	)
	obj := objr.object
	if obj == nil {
		fatalf(404, "Not Found", "The resource could not be found.")
	}

	h := a.w.Header()
	// add metadata
	obj.getMetadata(a)

	if r := a.req.Header.Get("Range"); r != "" {
		m := rangeRegexp.FindStringSubmatch(r)
		if m[2] != "" {
			start, _ = strconv.Atoi(m[2])
		}
		if m[3] != "" {
			end, _ = strconv.Atoi(m[3])
		}
	}

	max := func(a int, b int) int {
		if a > b {
			return a
		}
		return b
	}

	if manifest, ok := obj.meta["X-Object-Manifest"]; ok {
		var segments []io.Reader
		components := strings.SplitN(manifest[0], "/", 2)
		segContainer := a.user.Containers[components[0]]
		prefix := components[1]
		resp := segContainer.list("", "", prefix, "")
		sum := md5.New()
		cursor := 0
		size := 0
		for _, item := range resp {
			if obj, ok := item.(*object); ok {
				length := len(obj.data)
				size += length
				sum.Write([]byte(hex.EncodeToString(obj.checksum)))
				if start >= cursor+length {
					continue
				}
				segments = append(segments, bytes.NewReader(obj.data[max(0, start-cursor):]))
				cursor += length
			}
		}
		etag = sum.Sum(nil)
		if end == -1 {
			end = size
		}
		reader = io.LimitReader(io.MultiReader(segments...), int64(end-start))
	} else {
		if end == -1 {
			end = len(obj.data)
		}
		etag = obj.checksum
		reader = bytes.NewReader(obj.data[start:end])
	}

	h.Set("Content-Length", fmt.Sprint(end-start))
	h.Set("ETag", hex.EncodeToString(etag))
	h.Set("Last-Modified", obj.mtime.Format(http.TimeFormat))

	if a.req.Method == "HEAD" {
		return nil
	}

	// TODO avoid holding the lock when writing data.
	_, err := io.Copy(a.w, reader)
	if err != nil {
		// we can't do much except just log the fact.
		log.Printf("error writing data: %v", err)
	}
	return nil
}

// PUT on an object creates the object.
func (objr objectResource) put(a *action) interface{} {
	var expectHash []byte
	if c := a.req.Header.Get("ETag"); c != "" {
		var err error
		expectHash, err = hex.DecodeString(c)
		if err != nil || len(expectHash) != md5.Size {
			fatalf(400, "InvalidDigest", "The ETag you specified was invalid")
		}
	}
	sum := md5.New()
	// TODO avoid holding lock while reading data.
	data, err := ioutil.ReadAll(io.TeeReader(a.req.Body, sum))
	if err != nil {
		fatalf(400, "TODO", "read error")
	}
	gotHash := sum.Sum(nil)
	if expectHash != nil && bytes.Compare(gotHash, expectHash) != 0 {
		fatalf(422, "Bad ETag", "The ETag you specified did not match what we received")
	}
	if a.req.ContentLength >= 0 && int64(len(data)) != a.req.ContentLength {
		fatalf(400, "IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header")
	}

	// TODO is this correct, or should we erase all previous metadata?
	obj := objr.object
	if obj == nil {
		obj = &object{
			name: objr.name,
			metadata: metadata{
				meta: make(http.Header),
			},
		}
		a.user.Objects++
	} else {
		objr.container.bytes -= len(obj.data)
		a.user.BytesUsed -= int64(len(obj.data))
	}

	var content_type string
	if content_type = a.req.Header.Get("Content-Type"); content_type == "" {
		content_type = mime.TypeByExtension(obj.name)
		if content_type == "" {
			content_type = "application/octet-stream"
		}
	}

	// PUT request has been successful - save data and metadata
	obj.setMetadata(a, "object")
	obj.content_type = content_type
	obj.data = data
	obj.checksum = gotHash
	obj.mtime = time.Now().UTC()
	objr.container.objects[objr.name] = obj
	objr.container.bytes += len(data)
	a.user.BytesUsed += int64(len(data))

	h := a.w.Header()
	h.Set("ETag", hex.EncodeToString(obj.checksum))

	return nil
}

func (objr objectResource) delete(a *action) interface{} {
	if objr.object == nil {
		fatalf(404, "NoSuchKey", "The specified key does not exist.")
	}

	objr.container.bytes -= len(objr.object.data)
	a.user.BytesUsed -= int64(len(objr.object.data))
	delete(objr.container.objects, objr.name)
	a.user.Objects--
	return nil
}

func (objr objectResource) post(a *action) interface{} {
	obj := objr.object
	obj.setMetadata(a, "object")
	return nil
}

func (objr objectResource) copy(a *action) interface{} {
	if objr.object == nil {
		fatalf(404, "NoSuchKey", "The specified key does not exist.")
	}

	obj := objr.object
	destination := a.req.Header.Get("Destination")
	if destination == "" {
		fatalf(400, "Bad Request", "You must provide a Destination header")
	}

	var (
		obj2  *object
		objr2 objectResource
	)

	destURL, _ := url.Parse("/v1/AUTH_" + TEST_ACCOUNT + "/" + destination)
	r := a.srv.resourceForURL(destURL)
	switch t := r.(type) {
	case objectResource:
		objr2 = t
		if objr2.object == nil {
			obj2 = &object{
				name: objr2.name,
				metadata: metadata{
					meta: make(http.Header),
				},
			}
			a.user.Objects++
		} else {
			obj2 = objr2.object
			objr2.container.bytes -= len(obj2.data)
			a.user.BytesUsed -= int64(len(obj2.data))
		}
	default:
		fatalf(400, "Bad Request", "Destination must point to a valid object path")
	}

	obj2.content_type = obj.content_type
	obj2.data = obj.data
	obj2.checksum = obj.checksum
	obj2.mtime = time.Now()
	objr2.container.objects[objr2.name] = obj2
	objr2.container.bytes += len(obj.data)
	a.user.BytesUsed += int64(len(obj.data))

	for key, values := range obj.metadata.meta {
		obj2.metadata.meta[key] = values
	}
	obj2.setMetadata(a, "object")

	return nil
}

func (s *SwiftServer) serveHTTP(w http.ResponseWriter, req *http.Request) {
	// ignore error from ParseForm as it's usually spurious.
	req.ParseForm()

	s.mu.Lock()
	defer s.mu.Unlock()

	if DEBUG {
		log.Printf("swifttest %q %q", req.Method, req.URL)
	}
	a := &action{
		srv:   s,
		w:     w,
		req:   req,
		reqId: fmt.Sprintf("%09X", s.reqId),
	}
	s.reqId++

	var r resource
	defer func() {
		switch err := recover().(type) {
		case *swiftError:
			w.Header().Set("Content-Type", `text/plain; charset=utf-8`)
			http.Error(w, err.Message, err.statusCode)
		case nil:
		default:
			panic(err)
		}
	}()

	var resp interface{}

	if req.URL.String() == "/v1.0" {
		username := req.Header.Get("x-auth-user")
		key := req.Header.Get("x-auth-key")
		if acct, ok := s.Accounts[username]; ok {
			if acct.password == key {
				r := make([]byte, 16)
				_, _ = rand.Read(r)
				id := fmt.Sprintf("%X", r)
				w.Header().Set("X-Storage-Url", s.URL+"/AUTH_"+username)
				w.Header().Set("X-Auth-Token", "AUTH_tk"+string(id))
				w.Header().Set("X-Storage-Token", "AUTH_tk"+string(id))
				s.Sessions[id] = &session{
					username: username,
				}
				return
			}
		}
		panic(notAuthorized())
	}

	if req.URL.String() == "/info" {
		jsonMarshal(w, &swift.SwiftInfo{
			"swift": map[string]interface{}{
				"version": "1.2",
			},
			"tempurl": map[string]interface{}{
				"methods": []string{"GET", "HEAD", "PUT"},
			},
		})
		return
	}

	r = s.resourceForURL(req.URL)

	key := req.Header.Get("x-auth-token")
	signature := req.URL.Query().Get("temp_url_sig")
	expires := req.URL.Query().Get("temp_url_expires")
	if key == "" && signature != "" && expires != "" {
		accountName, _, _, _ := s.parseURL(req.URL)
		secretKey := ""
		if account, ok := s.Accounts[accountName]; ok {
			secretKey = account.meta.Get("X-Account-Meta-Temp-Url-Key")
		}

		get_hmac := func(method string) string {
			mac := hmac.New(sha1.New, []byte(secretKey))
			body := fmt.Sprintf("%s\n%s\n%s", method, expires, req.URL.Path)
			mac.Write([]byte(body))
			return hex.EncodeToString(mac.Sum(nil))
		}

		if req.Method == "HEAD" {
			if signature != get_hmac("GET") && signature != get_hmac("POST") && signature != get_hmac("PUT") {
				panic(notAuthorized())
			}
		} else if signature != get_hmac(req.Method) {
			panic(notAuthorized())
		}
	} else {
		session, ok := s.Sessions[key[7:]]
		if !ok {
			panic(notAuthorized())
		}

		a.user = s.Accounts[session.username]
	}

	switch req.Method {
	case "PUT":
		resp = r.put(a)
	case "GET", "HEAD":
		resp = r.get(a)
	case "DELETE":
		resp = r.delete(a)
	case "POST":
		resp = r.post(a)
	case "COPY":
		resp = r.copy(a)
	default:
		fatalf(400, "MethodNotAllowed", "unknown http request method %q", req.Method)
	}

	content_type := req.Header.Get("Content-Type")
	if resp != nil && req.Method != "HEAD" {
		if strings.HasPrefix(content_type, "application/json") ||
			req.URL.Query().Get("format") == "json" {
			jsonMarshal(w, resp)
		} else {
			switch r := resp.(type) {
			case string:
				w.Write([]byte(r))
			default:
				w.Write(resp.([]byte))
			}
		}
	}
}

func jsonMarshal(w io.Writer, x interface{}) {
	if err := json.NewEncoder(w).Encode(x); err != nil {
		panic(fmt.Errorf("error marshalling %#v: %v", x, err))
	}
}

var pathRegexp = regexp.MustCompile("/v1/AUTH_([a-zA-Z0-9]+)(/([^/]+)(/(.*))?)?")

func (srv *SwiftServer) parseURL(u *url.URL) (account string, container string, object string, err error) {
	m := pathRegexp.FindStringSubmatch(u.Path)
	if m == nil {
		return "", "", "", fmt.Errorf("Couldn't parse the specified URI")
	}
	account = m[1]
	container = m[3]
	object = m[5]
	return
}

// resourceForURL returns a resource object for the given URL.
func (srv *SwiftServer) resourceForURL(u *url.URL) (r resource) {
	accountName, containerName, objectName, err := srv.parseURL(u)

	if err != nil {
		fatalf(404, "InvalidURI", err.Error())
	}

	account, ok := srv.Accounts[accountName]
	if !ok {
		fatalf(404, "NoSuchAccount", "The specified account does not exist")
	}

	if containerName == "" {
		return rootResource{}
	}
	b := containerResource{
		name:      containerName,
		container: account.Containers[containerName],
	}

	if objectName == "" {
		return b
	}

	if b.container == nil {
		fatalf(404, "NoSuchContainer", "The specified container does not exist")
	}

	objr := objectResource{
		name:      objectName,
		version:   u.Query().Get("versionId"),
		container: b.container,
	}

	if obj := objr.container.objects[objr.name]; obj != nil {
		objr.object = obj
	}
	return objr
}

// nullResource has error stubs for all resource methods.
type nullResource struct{}

func notAllowed() interface{} {
	fatalf(400, "MethodNotAllowed", "The specified method is not allowed against this resource")
	return nil
}

func notAuthorized() interface{} {
	fatalf(401, "Unauthorized", "This server could not verify that you are authorized to access the document you requested.")
	return nil
}

func (nullResource) put(a *action) interface{}    { return notAllowed() }
func (nullResource) get(a *action) interface{}    { return notAllowed() }
func (nullResource) post(a *action) interface{}   { return notAllowed() }
func (nullResource) delete(a *action) interface{} { return notAllowed() }
func (nullResource) copy(a *action) interface{}   { return notAllowed() }

type rootResource struct{}

func (rootResource) put(a *action) interface{} { return notAllowed() }
func (rootResource) get(a *action) interface{} {
	marker := a.req.Form.Get("marker")
	prefix := a.req.Form.Get("prefix")
	format := a.req.URL.Query().Get("format")

	h := a.w.Header()

	h.Set("X-Account-Bytes-Used", strconv.Itoa(int(a.user.BytesUsed)))
	h.Set("X-Account-Container-Count", strconv.Itoa(int(a.user.Account.Containers)))
	h.Set("X-Account-Object-Count", strconv.Itoa(int(a.user.Objects)))

	// add metadata
	a.user.metadata.getMetadata(a)

	if a.req.Method == "HEAD" {
		return nil
	}

	var tmp orderedContainers
	// first get all matching objects and arrange them in alphabetical order.
	for _, container := range a.user.Containers {
		if strings.HasPrefix(container.name, prefix) {
			tmp = append(tmp, container)
		}
	}
	sort.Sort(tmp)

	resp := make([]Folder, 0)
	for _, container := range tmp {
		if container.name <= marker {
			continue
		}
		if format == "json" {
			resp = append(resp, Folder{
				Count: len(container.objects),
				Bytes: container.bytes,
				Name:  container.name,
			})
		} else {
			a.w.Write([]byte(container.name + "\n"))
		}
	}

	if format == "json" {
		return resp
	} else {
		return nil
	}
}

func (r rootResource) post(a *action) interface{} {
	a.user.metadata.setMetadata(a, "account")
	return nil
}

func (rootResource) delete(a *action) interface{} {
	if a.req.URL.Query().Get("bulk-delete") == "1" {
		fatalf(403, "Operation forbidden", "Bulk delete is not supported")
	}

	return notAllowed()
}

func (rootResource) copy(a *action) interface{} { return notAllowed() }

func NewSwiftServer(address string) (*SwiftServer, error) {
	var (
		l   net.Listener
		err error
	)
	if strings.Index(address, ":") == -1 {
		for port := 1024; port < 65535; port++ {
			addr := fmt.Sprintf("%s:%d", address, port)
			if l, err = net.Listen("tcp", addr); err == nil {
				address = addr
				break
			}
		}
	} else {
		l, err = net.Listen("tcp", address)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %v", address, err)
	}

	server := &SwiftServer{
		Listener: l,
		AuthURL:  "http://" + l.Addr().String() + "/v1.0",
		URL:      "http://" + l.Addr().String() + "/v1",
		Accounts: make(map[string]*account),
		Sessions: make(map[string]*session),
	}

	server.Accounts[TEST_ACCOUNT] = &account{
		password: TEST_ACCOUNT,
		metadata: metadata{
			meta: make(http.Header),
		},
		Containers: make(map[string]*container),
	}

	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		server.serveHTTP(w, req)
	}))

	return server, nil
}

func (srv *SwiftServer) Close() {
	srv.Listener.Close()
}
