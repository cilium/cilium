package fluent

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/bmizerany/assert"
)

const (
	RECV_BUF_LEN = 1024
)

// Conn is net.Conn with the parameters to be verified in the test
type Conn struct {
	net.Conn
	buf           []byte
	writeDeadline time.Time
}

func (c *Conn) Read(b []byte) (int, error) {
	copy(b, c.buf)
	return len(c.buf), nil
}

func (c *Conn) Write(b []byte) (int, error) {
	c.buf = make([]byte, len(b))
	copy(c.buf, b)
	return len(b), nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

func (c *Conn) Close() error {
	return nil
}

func init() {
	numProcs := runtime.NumCPU()
	if numProcs < 2 {
		numProcs = 2
	}
	runtime.GOMAXPROCS(numProcs)

	listener, err := net.Listen("tcp", "0.0.0.0:6666")
	if err != nil {
		println("error listening:", err.Error())
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				println("Error accept:", err.Error())
				return
			}
			go EchoFunc(conn)
		}
	}()
}

func EchoFunc(conn net.Conn) {
	for {
		buf := make([]byte, RECV_BUF_LEN)
		n, err := conn.Read(buf)
		if err != nil {
			println("Error reading:", err.Error())
			return
		}
		println("received ", n, " bytes of data =", string(buf))
	}
}

func Test_New_itShouldUseDefaultConfigValuesIfNoOtherProvided(t *testing.T) {
	f, _ := New(Config{})
	assert.Equal(t, f.Config.FluentPort, defaultPort)
	assert.Equal(t, f.Config.FluentHost, defaultHost)
	assert.Equal(t, f.Config.Timeout, defaultTimeout)
	assert.Equal(t, f.Config.WriteTimeout, defaultWriteTimeout)
	assert.Equal(t, f.Config.BufferLimit, defaultBufferLimit)
	assert.Equal(t, f.Config.FluentNetwork, defaultNetwork)
	assert.Equal(t, f.Config.FluentSocketPath, defaultSocketPath)
}

func Test_New_itShouldUseUnixDomainSocketIfUnixSocketSpecified(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows not supported")
	}
	socketFile := "/tmp/fluent-logger-golang.sock"
	network := "unix"
	l, err := net.Listen(network, socketFile)
	if err != nil {
		t.Error(err)
		return
	}
	defer l.Close()

	f, err := New(Config{
		FluentNetwork:    network,
		FluentSocketPath: socketFile})
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	assert.Equal(t, f.Config.FluentNetwork, network)
	assert.Equal(t, f.Config.FluentSocketPath, socketFile)

	socketFile = "/tmp/fluent-logger-golang-xxx.sock"
	network = "unixxxx"
	fUnknown, err := New(Config{
		FluentNetwork:    network,
		FluentSocketPath: socketFile})
	if _, ok := err.(net.UnknownNetworkError); !ok {
		t.Errorf("err type: %T", err)
	}
	if err == nil {
		t.Error(err)
		fUnknown.Close()
		return
	}
}

func Test_New_itShouldUseConfigValuesFromArguments(t *testing.T) {
	f, _ := New(Config{FluentPort: 6666, FluentHost: "foobarhost"})
	assert.Equal(t, f.Config.FluentPort, 6666)
	assert.Equal(t, f.Config.FluentHost, "foobarhost")
}

func Test_New_itShouldUseConfigValuesFromMashalAsJSONArgument(t *testing.T) {
	f, _ := New(Config{MarshalAsJSON: true})
	assert.Equal(t, f.Config.MarshalAsJSON, true)
}

func Test_send_WritePendingToConn(t *testing.T) {
	f := &Fluent{Config: Config{}, reconnecting: false}

	conn := &Conn{}
	f.conn = conn

	msg := "This is test writing."
	bmsg := []byte(msg)
	f.pending = append(f.pending, bmsg...)

	err := f.send()
	if err != nil {
		t.Error(err)
	}

	rcv := make([]byte, len(conn.buf))
	_, err = conn.Read(rcv)
	if string(rcv) != msg {
		t.Errorf("got %s, except %s", string(rcv), msg)
	}
}

func Test_MarshalAsMsgpack(t *testing.T) {
	f := &Fluent{Config: Config{}, reconnecting: false}

	conn := &Conn{}
	f.conn = conn

	tag := "tag"
	var data = map[string]string{
		"foo":  "bar",
		"hoge": "hoge"}
	tm := time.Unix(1267867237, 0)
	result, err := f.EncodeData(tag, tm, data)

	if err != nil {
		t.Error(err)
	}
	actual := string(result)

	// map entries are disordered in golang
	expected1 := "\x94\xA3tag\xD2K\x92\u001Ee\x82\xA3foo\xA3bar\xA4hoge\xA4hoge\xC0"
	expected2 := "\x94\xA3tag\xD2K\x92\u001Ee\x82\xA4hoge\xA4hoge\xA3foo\xA3bar\xC0"
	if actual != expected1 && actual != expected2 {
		t.Errorf("got %x,\n         except %x\n             or %x", actual, expected1, expected2)
	}
}

func Test_SubSecondPrecision(t *testing.T) {
	// Setup the test subject
	fluent := &Fluent{
		Config: Config{
			SubSecondPrecision: true,
		},
		reconnecting: false,
	}
	fluent.conn = &Conn{}

	// Exercise the test subject
	timestamp := time.Unix(1267867237, 256)
	encodedData, err := fluent.EncodeData("tag", timestamp, map[string]string{
		"foo": "bar",
	})

	// Assert no encoding errors and that the timestamp has been encoded into
	// the message as expected.
	if err != nil {
		t.Error(err)
	}

	expected := "\x94\xA3tag\xC7\x08\x00K\x92\u001Ee\x00\x00\x01\x00\x81\xA3foo\xA3bar\xC0"
	actual := string(encodedData)
	assert.Equal(t, expected, actual)
}

func Test_MarshalAsJSON(t *testing.T) {
	f := &Fluent{Config: Config{MarshalAsJSON: true}, reconnecting: false}

	conn := &Conn{}
	f.conn = conn

	var data = map[string]string{
		"foo":  "bar",
		"hoge": "hoge"}
	tm := time.Unix(1267867237, 0)
	result, err := f.EncodeData("tag", tm, data)

	if err != nil {
		t.Error(err)
	}
	// json.Encode marshals map keys in the order, so this expectation is safe
	expected := `["tag",1267867237,{"foo":"bar","hoge":"hoge"},null]`
	actual := string(result)
	if actual != expected {
		t.Errorf("got %s, except %s", actual, expected)
	}
}

func TestJsonConfig(t *testing.T) {
	b, err := ioutil.ReadFile(`testdata/config.json`)
	if err != nil {
		t.Error(err)
	}
	var got Config
	expect := Config{
		FluentPort:       8888,
		FluentHost:       "localhost",
		FluentNetwork:    "tcp",
		FluentSocketPath: "/var/tmp/fluent.sock",
		Timeout:          3000,
		WriteTimeout:     6000,
		BufferLimit:      200,
		RetryWait:        5,
		MaxRetry:         3,
		TagPrefix:        "fluent",
		AsyncConnect:     false,
		MarshalAsJSON:    true,
	}

	err = json.Unmarshal(b, &got)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(expect, got) {
		t.Errorf("got %v, except %v", got, expect)
	}
}

func TestAsyncConnect(t *testing.T) {
	type result struct {
		f   *Fluent
		err error
	}
	ch := make(chan result, 1)
	go func() {
		config := Config{
			FluentPort:   8888,
			AsyncConnect: true,
		}
		f, err := New(config)
		ch <- result{f: f, err: err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			t.Errorf("fluent.New() failed with %#v", res.err)
			return
		}
		res.f.Close()
	case <-time.After(time.Millisecond * 500):
		t.Error("AsyncConnect must not block")
	}
}

func Test_PostWithTimeNotTimeOut(t *testing.T) {
	f, err := New(Config{
		FluentPort:    6666,
		AsyncConnect:  false,
		MarshalAsJSON: true, // easy to check equality
	})
	if err != nil {
		t.Error(err)
		return
	}

	var testData = []struct {
		in  map[string]string
		out string
	}{
		{
			map[string]string{"foo": "bar"},
			"[\"tag_name\",1482493046,{\"foo\":\"bar\"},null]",
		},
		{
			map[string]string{"fuga": "bar", "hoge": "fuga"},
			"[\"tag_name\",1482493046,{\"fuga\":\"bar\",\"hoge\":\"fuga\"},null]",
		},
	}
	for _, tt := range testData {
		conn := &Conn{}
		f.conn = conn

		err = f.PostWithTime("tag_name", time.Unix(1482493046, 0), tt.in)
		if err != nil {
			t.Errorf("in=%s, err=%s", tt.in, err)
		}

		rcv := make([]byte, len(conn.buf))
		_, err = conn.Read(rcv)
		if string(rcv) != tt.out {
			t.Errorf("got %s, except %s", string(rcv), tt.out)
		}

		if !conn.writeDeadline.IsZero() {
			t.Errorf("got %s, except 0", conn.writeDeadline)
		}
	}
}

func Test_PostMsgpMarshaler(t *testing.T) {
	f, err := New(Config{
		FluentPort:    6666,
		AsyncConnect:  false,
		MarshalAsJSON: true, // easy to check equality
	})
	if err != nil {
		t.Error(err)
		return
	}

	var testData = []struct {
		in  *TestMessage
		out string
	}{
		{
			&TestMessage{Foo: "bar"},
			"[\"tag_name\",1482493046,{\"foo\":\"bar\"},null]",
		},
	}
	for _, tt := range testData {
		conn := &Conn{}
		f.conn = conn

		err = f.PostWithTime("tag_name", time.Unix(1482493046, 0), tt.in)
		if err != nil {
			t.Errorf("in=%s, err=%s", tt.in, err)
		}

		rcv := make([]byte, len(conn.buf))
		_, err = conn.Read(rcv)
		if string(rcv) != tt.out {
			t.Errorf("got %s, except %s", string(rcv), tt.out)
		}

		if !conn.writeDeadline.IsZero() {
			t.Errorf("got %s, except 0", conn.writeDeadline)
		}
	}
}

func Benchmark_PostWithShortMessage(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := map[string]string{"message": "Hello World"}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_PostWithShortMessageMarshalAsJSON(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{MarshalAsJSON: true})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := map[string]string{"message": "Hello World"}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_LogWithChunks(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := map[string]string{"msg": "sdfsdsdfdsfdsddddfsdfsdsdfdsfdsddddfsdfsdsdfdsfdsddddfsdfsdsdfdsfdsddddfsdfsdsdfdsfdsddddfsdfsdsdfdsfdsddddfsdfsdsdfdsfdsddddfsdfsdsdfdsfdsddddf"}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_PostWithStruct(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := struct {
		Name string `msg:"msgnamename"`
	}{
		"john smith",
	}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_PostWithStructTaggedAsCodec(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := struct {
		Name string `codec:"codecname"`
	}{
		"john smith",
	}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_PostWithStructWithoutTag(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := struct {
		Name string
	}{
		"john smith",
	}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_PostWithMapString(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := map[string]string{
		"foo": "bar",
	}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_PostWithMsgpMarshaler(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := &TestMessage{Foo: "bar"}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_PostWithMapSlice(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := map[string][]int{
		"foo": {1, 2, 3},
	}
	for i := 0; i < b.N; i++ {
		if err := f.Post("tag", data); err != nil {
			panic(err)
		}
	}
}

func Benchmark_PostWithMapStringAndTime(b *testing.B) {
	b.StopTimer()
	f, err := New(Config{})
	if err != nil {
		panic(err)
	}

	b.StartTimer()
	data := map[string]string{
		"foo": "bar",
	}
	tm := time.Now()
	for i := 0; i < b.N; i++ {
		if err := f.PostWithTime("tag", tm, data); err != nil {
			panic(err)
		}
	}
}
