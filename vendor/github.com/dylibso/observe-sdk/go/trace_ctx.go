package observe

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
)

// TraceCtx holds the context for a trace, or wasm module invocation.
// It collects holds a channel to the Adapter and from the wazero Listener
// It will collect events throughout the invocation of the function. Calling
// Finish() will then submit those events to the Adapter to be processed and sent
type TraceCtx struct {
	adapter     chan TraceEvent
	raw         chan RawEvent
	events      []Event
	stack       []CallEvent
	Options     *Options
	names       map[uint32]string
	telemetryId TelemetryId
	adapterMeta interface{}
}

// Creates a new TraceCtx. Used internally by the Adapter. The user should create the trace context from the Adapter.
func newTraceCtx(ctx context.Context, eventsChan chan TraceEvent, r wazero.Runtime, data []byte, opts *Options) (*TraceCtx, error) {
	names, err := parseNames(data)
	if err != nil {
		return nil, err
	}

	if opts.ChannelBufferSize == 0 {
		opts.ChannelBufferSize = 64 // set a reasonable minimum here so unset option doesn't block execution on an unbuffered channel
	}

	traceCtx := &TraceCtx{
		adapter:     eventsChan,
		raw:         make(chan RawEvent, opts.ChannelBufferSize),
		names:       names,
		telemetryId: NewTraceId(),
		Options:     opts,
	}

	err = traceCtx.init(ctx, r)
	if err != nil {
		return nil, err
	}

	return traceCtx, nil
}

func (t *TraceCtx) SetTraceId(id string) error {
	return t.telemetryId.FromString(id)
}

func (t *TraceCtx) Metadata(metadata interface{}) {
	t.adapterMeta = metadata
}

// Finish() will stop the trace and send the
// TraceEvent payload to the adapter
func (t *TraceCtx) Finish() {
	traceEvent := TraceEvent{
		Events:      t.events,
		TelemetryId: t.telemetryId,
		AdapterMeta: t.adapterMeta,
	}
	t.adapter <- traceEvent
	// clear the trace context
	t.events = nil
	t.telemetryId = NewTraceId()
}

// Attaches the wazero FunctionListener to the context
func (t *TraceCtx) withListener(ctx context.Context) context.Context {
	return experimental.WithFunctionListenerFactory(ctx, t)
}

// Initializes the TraceCtx. This connects up the channels with events from the FunctionListener.
// Should only be called once.
func (t *TraceCtx) init(ctx context.Context, r wazero.Runtime) error {
	ctx = t.withListener(ctx)

	if r.Module("dylibso_observe") != nil || r.Module("dylibso:observe/instrument") != nil ||
		r.Module("dylibso:observe/api") != nil {
		return nil
	}

	enterFunc := func(ctx context.Context, m api.Module, i uint32) {
		start := time.Now()
		ev := <-t.raw

		t.enter(ev, start)
	}

	spanEnterFunc := func(ctx context.Context, m api.Module, ptr uint32, len uint32) {
		start := time.Now()
		ev := <-t.raw

		functionName, ok := m.Memory().Read(ptr, len)
		if !ok {
			log.Printf("span_enter: failed to read memory at offset %v with length %v\n", ptr, len)
		}

		ev.FunctionName = string(functionName)

		t.enter(ev, start)
	}

	oldSpanEnterFunc := func(ctx context.Context, m api.Module, ptr uint64, len uint32) {
		spanEnterFunc(ctx, m, uint32(ptr), len)
	}

	exitFunc := func(ctx context.Context, i uint32) {
		end := time.Now()
		ev := <-t.raw

		t.exit(ev, end)
	}

	spanExitFunc := func(ctx context.Context, m api.Module) {
		end := time.Now()
		ev := <-t.raw

		t.exit(ev, end)
	}

	memoryGrowFunc := func(ctx context.Context, amt uint32) {
		ev := <-t.raw
		if ev.Kind != RawMemoryGrow {
			log.Println("Expected event", MemoryGrow, "but got", ev.Kind)
			return
		}

		if len(t.stack) > 0 {
			f := t.stack[len(t.stack)-1]
			ev.FunctionIndex = f.FunctionIndex()
			ev.FunctionName = f.FunctionName()
		}

		event := MemoryGrowEvent{
			Raw:  ev,
			Time: time.Now(),
		}

		fn, ok := t.popFunction()
		if !ok {
			t.events = append(t.events, event)
			return
		}
		fn.within = append(fn.within, event)
		t.pushFunction(fn)
	}

	metricFunc := func(ctx context.Context, m api.Module, f uint32, ptr uint32, l uint32) {
		format := MetricFormat(f)
		buffer, ok := m.Memory().Read(ptr, l)
		if !ok {
			log.Printf("metric: failed to read memory at offset %v with length %v\n", ptr, l)
		}

		event := MetricEvent{
			Time:    time.Now(),
			Format:  format,
			Message: string(buffer),
		}

		fn, ok := t.popFunction()
		if !ok {
			t.events = append(t.events, event)
			return
		}
		fn.within = append(fn.within, event)
		t.pushFunction(fn)
	}

	oldMetricFunc := func(ctx context.Context, m api.Module, f uint32, ptr uint64, len uint32) {
		metricFunc(ctx, m, f, uint32(ptr), len)
	}

	spanTagsFunc := func(ctx context.Context, m api.Module, ptr uint32, len uint32) {
		buffer, ok := m.Memory().Read(ptr, len)
		if !ok {
			log.Printf("span-tags: failed to read memory at offset %v with length %v\n", ptr, len)
		}

		ev := <-t.raw
		if ev.Kind != RawSpanTags {
			log.Println("Expected event", SpanTags, "but got", ev.Kind)
			return
		}

		event := SpanTagsEvent{
			Time: time.Now(),
			Raw:  ev,
			Tags: strings.Split(string(buffer), ","),
		}

		fn, ok := t.popFunction()
		if !ok {
			t.events = append(t.events, event)
			return
		}
		fn.within = append(fn.within, event)
		t.pushFunction(fn)
	}

	oldSpanTagsFunc := func(ctx context.Context, m api.Module, ptr uint64, len uint32) {
		spanTagsFunc(ctx, m, uint32(ptr), len)
	}

	logFunc := func(ctx context.Context, m api.Module, l uint32, ptr uint32, len uint32) {
		if l < uint32(Error) || l > uint32(Debug) {
			log.Printf("log: invalid log level %v\n", l)
		}

		level := LogLevel(l)

		buffer, ok := m.Memory().Read(ptr, len)
		if !ok {
			log.Printf("log: failed to read memory at offset %v with length %v\n", ptr, len)
		}

		event := LogEvent{
			Time:    time.Now(),
			Level:   level,
			Message: string(buffer),
		}

		fn, ok := t.popFunction()
		if !ok {
			t.events = append(t.events, event)
			return
		}
		fn.within = append(fn.within, event)
		t.pushFunction(fn)
	}

	oldLogFunc := func(ctx context.Context, m api.Module, l uint32, ptr uint64, len uint32) {
		logFunc(ctx, m, l, uint32(ptr), len)
	}

	// instrument api
	{
		instrument := r.NewHostModuleBuilder("dylibso:observe/instrument")
		instrFunctions := instrument.NewFunctionBuilder()
		instrFunctions.WithFunc(enterFunc).Export("enter")
		instrFunctions.WithFunc(exitFunc).Export("exit")
		instrFunctions.WithFunc(memoryGrowFunc).Export("memory-grow")
		_, err := instrument.Instantiate(ctx)
		if err != nil {
			return err
		}
	}

	// manual api
	{
		api := r.NewHostModuleBuilder("dylibso:observe/api")
		apiFunctions := api.NewFunctionBuilder()
		apiFunctions.WithFunc(spanEnterFunc).Export("span-enter")
		apiFunctions.WithFunc(spanExitFunc).Export("span-exit")
		apiFunctions.WithFunc(spanTagsFunc).Export("span-tags")
		apiFunctions.WithFunc(metricFunc).Export("metric")
		apiFunctions.WithFunc(logFunc).Export("log")
		_, err := api.Instantiate(ctx)
		if err != nil {
			return err
		}
	}

	//old api (combined instrument and manual api)
	{
		observe := r.NewHostModuleBuilder("dylibso_observe")
		observeFunctions := observe.NewFunctionBuilder()
		observeFunctions.WithFunc(enterFunc).Export("instrument_enter")
		observeFunctions.WithFunc(exitFunc).Export("instrument_exit")
		observeFunctions.WithFunc(memoryGrowFunc).Export("instrument_memory_grow")
		observeFunctions.WithFunc(oldSpanEnterFunc).Export("span_enter")
		observeFunctions.WithFunc(spanExitFunc).Export("span_exit")
		observeFunctions.WithFunc(oldSpanTagsFunc).Export("span_tags")
		observeFunctions.WithFunc(oldMetricFunc).Export("metric")
		observeFunctions.WithFunc(oldLogFunc).Export("log")
		_, err := observe.Instantiate(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *TraceCtx) enter(ev RawEvent, start time.Time) {
	if ev.Kind != RawEnter {
		log.Println("Expected event", RawEnter, "but got", ev.Kind)
	}
	t.pushFunction(CallEvent{Raw: []RawEvent{ev}, Time: start})
}

func (t *TraceCtx) exit(ev RawEvent, end time.Time) {

	if ev.Kind != RawExit {
		log.Println("Expected event", RawExit, "but got", ev.Kind)
		return
	}
	fn, ok := t.peekFunction()
	if !ok {
		log.Println("Expected values on started function stack, but none were found")
		return
	}
	if ev.FunctionIndex != fn.FunctionIndex() {
		log.Println("Expected call to", ev.FunctionIndex, "but found call to", fn.FunctionIndex())
		return
	}

	fn, _ = t.popFunction()
	fn.Stop(end)
	fn.Raw = append(fn.Raw, ev)

	// if there is no function left to pop, we are exiting the root function of the trace
	f, ok := t.peekFunction()
	if !ok {
		t.events = append(t.events, fn)
		return
	}

	// if the function duration is less than minimum duration, disregard
	funcDuration := fn.Duration.Microseconds()
	minSpanDuration := t.Options.SpanFilter.MinDuration.Microseconds()
	if funcDuration < minSpanDuration {
		// check for memory allocations and attribute them to the parent span
		f, ok = t.popFunction()
		if ok {
			for _, ev := range fn.within {
				switch e := ev.(type) {
				case MemoryGrowEvent:
					f.within = append(f.within, e)
				}
			}
			t.pushFunction(f)
		}
		return
	}

	// the function is within another function
	f, ok = t.popFunction()
	if ok {
		f.within = append(f.within, fn)
		t.pushFunction(f)
	}
}

// Pushes a function onto the stack
func (t *TraceCtx) pushFunction(ev CallEvent) {
	t.stack = append(t.stack, ev)
}

// Pops a function off the stack
func (t *TraceCtx) popFunction() (CallEvent, bool) {
	if len(t.stack) == 0 {
		return CallEvent{}, false
	}

	event := t.stack[len(t.stack)-1]
	t.stack = t.stack[:len(t.stack)-1]

	return event, true
}

// Peek at the function on top of the stack without modifying
func (t *TraceCtx) peekFunction() (CallEvent, bool) {
	if len(t.stack) == 0 {
		return CallEvent{}, false
	}

	return t.stack[len(t.stack)-1], true
}
