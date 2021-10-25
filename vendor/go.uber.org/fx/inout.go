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

package fx

import "go.uber.org/dig"

// In can be embedded in a constructor's parameter struct to take advantage of
// advanced dependency injection features.
//
// Modules should take a single parameter struct that embeds an In in order to
// provide a forward-compatible API: since adding fields to a struct is
// backward-compatible, modules can then add optional dependencies in minor
// releases.
//
// Parameter Structs
//
// Fx constructors declare their dependencies as function parameters. This can
// quickly become unreadable if the constructor has a lot of dependencies.
//
//   func NewHandler(users *UserGateway, comments *CommentGateway, posts *PostGateway, votes *VoteGateway, authz *AuthZGateway) *Handler {
//     // ...
//   }
//
// To improve the readability of constructors like this, create a struct that
// lists all the dependencies as fields and change the function to accept that
// struct instead. The new struct is called a parameter struct.
//
// Fx has first class support for parameter structs: any struct embedding
// fx.In gets treated as a parameter struct, so the individual fields in the
// struct are supplied via dependency injection. Using a parameter struct, we
// can make the constructor above much more readable:
//
//   type HandlerParams struct {
//     fx.In
//
//     Users    *UserGateway
//     Comments *CommentGateway
//     Posts    *PostGateway
//     Votes    *VoteGateway
//     AuthZ    *AuthZGateway
//   }
//
//   func NewHandler(p HandlerParams) *Handler {
//     // ...
//   }
//
// Though it's rarely a good idea, constructors can receive any combination of
// parameter structs and parameters.
//
//   func NewHandler(p HandlerParams, l *log.Logger) *Handler {
//     // ...
//   }
//
// Optional Dependencies
//
// Constructors often have soft dependencies on some types: if those types are
// missing, they can operate in a degraded state. Fx supports optional
// dependencies via the `optional:"true"` tag to fields on parameter structs.
//
//   type UserGatewayParams struct {
//     fx.In
//
//     Conn  *sql.DB
//     Cache *redis.Client `optional:"true"`
//   }
//
// If an optional field isn't available in the container, the constructor
// receives the field's zero value.
//
//   func NewUserGateway(p UserGatewayParams, log *log.Logger) (*UserGateway, error) {
//     if p.Cache == nil {
//       log.Print("Caching disabled")
//     }
//     // ...
//   }
//
// Constructors that declare optional dependencies MUST gracefully handle
// situations in which those dependencies are absent.
//
// The optional tag also allows adding new dependencies without breaking
// existing consumers of the constructor.
//
// Named Values
//
// Some use cases require the application container to hold multiple values of
// the same type. For details on producing named values, see the documentation
// for the Out type.
//
// Fx allows functions to consume named values via the `name:".."` tag on
// parameter structs. Note that both the name AND type of the fields on the
// parameter struct must match the corresponding result struct.
//
//   type GatewayParams struct {
//     fx.In
//
//     WriteToConn  *sql.DB `name:"rw"`
//     ReadFromConn *sql.DB `name:"ro"`
//   }
//
// The name tag may be combined with the optional tag to declare the
// dependency optional.
//
//   type GatewayParams struct {
//     fx.In
//
//     WriteToConn  *sql.DB `name:"rw"`
//     ReadFromConn *sql.DB `name:"ro" optional:"true"`
//   }
//
//   func NewCommentGateway(p GatewayParams, log *log.Logger) (*CommentGateway, error) {
//     if p.ReadFromConn == nil {
//       log.Print("Warning: Using RW connection for reads")
//       p.ReadFromConn = p.WriteToConn
//     }
//     // ...
//   }
//
// Value Groups
//
// To make it easier to produce and consume many values of the same type, Fx
// supports named, unordered collections called value groups. For details on
// producing value groups, see the documentation for the Out type.
//
// Functions can depend on a value group by requesting a slice tagged with
// `group:".."`. This will execute all constructors that provide a value to
// that group in an unspecified order, then collect all the results into a
// single slice. Keep in mind that this makes the types of the parameter and
// result struct fields different: if a group of constructors each returns
// type T, parameter structs consuming the group must use a field of type []T.
//
//   type ServerParams struct {
//     fx.In
//
//     Handlers []Handler `group:"server"`
//   }
//
//   func NewServer(p ServerParams) *Server {
//     server := newServer()
//     for _, h := range p.Handlers {
//       server.Register(h)
//     }
//     return server
//   }
//
// Note that values in a value group are unordered. Fx makes no guarantees
// about the order in which these values will be produced.
//
// Unexported fields
//
// By default, a type that embeds fx.In may not have any unexported fields. The
// following will return an error if used with Fx.
//
//   type Params struct {
//     fx.In
//
//     Logger *zap.Logger
//     mu     sync.Mutex
//   }
//
// If you have need of unexported fields on such a type, you may opt-into
// ignoring unexported fields by adding the ignore-unexported struct tag to the
// fx.In. For example,
//
//   type Params struct {
//     fx.In `ignore-unexported:"true"`
//
//     Logger *zap.Logger
//     mu     sync.Mutex
//   }
type In = dig.In

// Out is the inverse of In: it can be embedded in result structs to take
// advantage of advanced features.
//
// Modules should return a single result struct that embeds an Out in order to
// provide a forward-compatible API: since adding fields to a struct is
// backward-compatible, minor releases can provide additional types.
//
// Result Structs
//
// Result structs are the inverse of parameter structs (discussed in the In
// documentation). These structs represent multiple outputs from a
// single function as fields. Fx treats all structs embedding fx.Out as result
// structs, so other constructors can rely on the result struct's fields
// directly.
//
// Without result structs, we sometimes have function definitions like this:
//
//   func SetupGateways(conn *sql.DB) (*UserGateway, *CommentGateway, *PostGateway, error) {
//     // ...
//   }
//
// With result structs, we can make this both more readable and easier to
// modify in the future:
//
//  type Gateways struct {
//    fx.Out
//
//    Users    *UserGateway
//    Comments *CommentGateway
//    Posts    *PostGateway
//  }
//
//  func SetupGateways(conn *sql.DB) (Gateways, error) {
//    // ...
//  }
//
// Named Values
//
// Some use cases require the application container to hold multiple values of
// the same type. For details on consuming named values, see the documentation
// for the In type.
//
// A constructor that produces a result struct can tag any field with
// `name:".."` to have the corresponding value added to the graph under the
// specified name. An application may contain at most one unnamed value of a
// given type, but may contain any number of named values of the same type.
//
//   type ConnectionResult struct {
//     fx.Out
//
//     ReadWrite *sql.DB `name:"rw"`
//     ReadOnly  *sql.DB `name:"ro"`
//   }
//
//   func ConnectToDatabase(...) (ConnectionResult, error) {
//     // ...
//     return ConnectionResult{ReadWrite: rw, ReadOnly:  ro}, nil
//   }
//
// Value Groups
//
// To make it easier to produce and consume many values of the same type, Fx
// supports named, unordered collections called value groups. For details on
// consuming value groups, see the documentation for the In type.
//
// Constructors can send values into value groups by returning a result struct
// tagged with `group:".."`.
//
//   type HandlerResult struct {
//     fx.Out
//
//     Handler Handler `group:"server"`
//   }
//
//   func NewHelloHandler() HandlerResult {
//     // ...
//   }
//
//   func NewEchoHandler() HandlerResult {
//     // ...
//   }
//
// Any number of constructors may provide values to this named collection, but
// the ordering of the final collection is unspecified. Keep in mind that
// value groups require parameter and result structs to use fields with
// different types: if a group of constructors each returns type T, parameter
// structs consuming the group must use a field of type []T.
//
// To provide multiple values for a group from a result struct, produce a
// slice and use the `,flatten` option on the group tag. This indicates that
// each element in the slice should be injected into the group individually.
//
//   type IntResult struct {
//     fx.Out
//
//     Handler []int `group:"server"`         // Consume as [][]int
//     Handler []int `group:"server,flatten"` // Consume as []int
//   }
type Out = dig.Out
