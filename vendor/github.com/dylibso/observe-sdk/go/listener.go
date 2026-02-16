package observe

import (
	"context"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
)

// Implements the NewListener() method to satisfy the FunctionListener interface
func (t *TraceCtx) NewListener(def api.FunctionDefinition) experimental.FunctionListener {
	if def.GoFunction() == nil {
		return nil
	}
	return t
}

// Implements the NewFunctionListener() method to satisfy the FunctionListener interface
func (t *TraceCtx) NewFunctionListener(_ api.FunctionDefinition) experimental.FunctionListener {
	return t
}

// Implements the Before() method to satisfy the FunctionListener interface.
// This takes events from the wazero runtime and sends them to the `raw` channel on the TraceCtx.
func (t *TraceCtx) Before(ctx context.Context, _ api.Module, def api.FunctionDefinition, inputs []uint64, stack experimental.StackIterator) {
	var event RawEvent
	name := def.Name()

	switch name {
	case "enter":
		fallthrough
	case "instrument_enter":
		event.Kind = RawEnter
		event.FunctionIndex = uint32(inputs[0])
		event.FunctionName = t.names[event.FunctionIndex]
	case "exit":
		fallthrough
	case "instrument_exit":
		event.Kind = RawExit
		event.FunctionIndex = uint32(inputs[0])
		event.FunctionName = t.names[event.FunctionIndex]
	case "memory-grow":
		fallthrough
	case "instrument_memory_grow":
		event.Kind = RawMemoryGrow
		event.MemoryGrowAmount = uint32(inputs[0])

		// manual events
	case "span-enter":
		fallthrough
	case "span_enter":
		event.Kind = RawEnter
	case "span-exit":
		fallthrough
	case "span_exit":
		event.Kind = RawExit
	case "span-tags":
		fallthrough
	case "span_tags":
		event.Kind = RawSpanTags
	case "metric":
		return
	case "log":
		return
	default:
		event.Kind = RawUnknownEvent
	}
	for stack.Next() {
		f := stack.Function()
		event.Stack = append(event.Stack, f)
	}
	t.raw <- event
}

// Null implementation of the After() method to satisfy the FunctionListener interface.
func (t *TraceCtx) After(context.Context, api.Module, api.FunctionDefinition, []uint64) {}

// Null implementation of the Abort() method to satisfy the FunctionListener interface.
func (t *TraceCtx) Abort(context.Context, api.Module, api.FunctionDefinition, error) {}
