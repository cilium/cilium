// Copyright (c) 2019 Uber Technologies, Inc.
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

// Package fx is a framework that makes it easy to build applications out of
// reusable, composable modules.
//
// Fx applications use dependency injection to eliminate globals without the
// tedium of manually wiring together function calls. Unlike other approaches
// to dependency injection, Fx works with plain Go functions: you don't need
// to use struct tags or embed special types, so Fx automatically works well
// with most Go packages.
//
// Basic usage is explained in the package-level example below. If you're new
// to Fx, start there! Advanced features, including named instances, optional
// parameters, and value groups, are explained under the In and Out types.
//
// Testing Fx Applications
//
// To test functions that use the Lifecycle type or to write end-to-end tests
// of your Fx application, use the helper functions and types provided by the
// go.uber.org/fx/fxtest package.
package fx // import "go.uber.org/fx"
