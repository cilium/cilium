// Copyright (c) 2023 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package dig

// CallbackInfo contains information about a provided function or decorator
// called by Dig, and is passed to a [Callback] registered with
// [WithProviderCallback] or [WithDecoratorCallback].
type CallbackInfo struct {

	// Name is the name of the function in the format:
	// <package_name>.<function_name>
	Name string

	// Error contains the error returned by the [Callback]'s associated
	// function, if any. When used in conjunction with [RecoverFromPanics],
	// this will be set to a [PanicError] when the function panics.
	Error error
}

// Callback is a function that can be registered with a provided function
// or decorator with [WithCallback] to cause it to be called after the
// provided function or decorator is run.
type Callback func(CallbackInfo)

// WithProviderCallback returns a [ProvideOption] which has Dig call
// the passed in [Callback] after the corresponding constructor finishes running.
//
// For example, the following prints a completion message
// after "myConstructor" finishes, including the error if any:
//
//	c := dig.New()
//	myCallback := func(ci CallbackInfo) {
//		var errorAdd string
//		if ci.Error != nil {
//			errorAdd = fmt.Sprintf("with error: %v", ci.Error)
//		}
//		fmt.Printf("%q finished%v", ci.Name, errorAdd)
//	}
//	c.Provide(myConstructor, WithProviderCallback(myCallback)),
//
// Callbacks can also be specified for Decorators with [WithDecoratorCallback].
//
// See [CallbackInfo] for more info on the information passed to the [Callback].
func WithProviderCallback(callback Callback) ProvideOption {
	return withCallbackOption{
		callback: callback,
	}
}

// WithDecoratorCallback returns a [DecorateOption] which has Dig call
// the passed in [Callback] after the corresponding decorator finishes running.
//
// For example, the following prints a completion message
// after "myDecorator" finishes, including the error if any:
//
//	c := dig.New()
//	myCallback := func(ci CallbackInfo) {
//		var errorAdd string
//		if ci.Error != nil {
//			errorAdd = fmt.Sprintf("with error: %v", ci.Error)
//		}
//		fmt.Printf("%q finished%v", ci.Name, errorAdd)
//	}
//	c.Decorate(myDecorator, WithDecoratorCallback(myCallback)),
//
// Callbacks can also be specified for Constructors with [WithProviderCallback].
//
// See [CallbackInfo] for more info on the information passed to the [Callback].
func WithDecoratorCallback(callback Callback) DecorateOption {
	return withCallbackOption{
		callback: callback,
	}
}

type withCallbackOption struct {
	callback Callback
}

var (
	_ ProvideOption  = withCallbackOption{}
	_ DecorateOption = withCallbackOption{}
)

func (o withCallbackOption) applyProvideOption(po *provideOptions) {
	po.Callback = o.callback
}

func (o withCallbackOption) apply(do *decorateOptions) {
	do.Callback = o.callback
}
