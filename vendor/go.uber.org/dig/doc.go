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

// Package dig provides an opinionated way of resolving object dependencies.
//
// # Status
//
// STABLE. No breaking changes will be made in this major version.
//
// # Container
//
// Dig exposes type Container as an object capable of resolving a directed
// acyclic dependency graph. Use the New function to create one.
//
//	c := dig.New()
//
// # Provide
//
// Constructors for different types are added to the container by using the
// Provide method. A constructor can declare a dependency on another type by
// simply adding it as a function parameter. Dependencies for a type can be
// added to the graph both, before and after the type was added.
//
//	err := c.Provide(func(conn *sql.DB) (*UserGateway, error) {
//	  // ...
//	})
//	if err != nil {
//	  // ...
//	}
//
//	if err := c.Provide(newDBConnection); err != nil {
//	  // ...
//	}
//
// Multiple constructors can rely on the same type. The container creates a
// singleton for each retained type, instantiating it at most once when
// requested directly or as a dependency of another type.
//
//	err := c.Provide(func(conn *sql.DB) *CommentGateway {
//	  // ...
//	})
//	if err != nil {
//	  // ...
//	}
//
// Constructors can declare any number of dependencies as parameters and
// optionally, return errors.
//
//	err := c.Provide(func(u *UserGateway, c *CommentGateway) (*RequestHandler, error) {
//	  // ...
//	})
//	if err != nil {
//	  // ...
//	}
//
//	if err := c.Provide(newHTTPServer); err != nil {
//	  // ...
//	}
//
// Constructors can also return multiple results to add multiple types to the
// container.
//
//	err := c.Provide(func(conn *sql.DB) (*UserGateway, *CommentGateway, error) {
//	  // ...
//	})
//	if err != nil {
//	  // ...
//	}
//
// Constructors that accept a variadic number of arguments are treated as if
// they don't have those arguments. That is,
//
//	func NewVoteGateway(db *sql.DB, options ...Option) *VoteGateway
//
// Is treated the same as,
//
//	func NewVoteGateway(db *sql.DB) *VoteGateway
//
// The constructor will be called with all other dependencies and no variadic
// arguments.
//
// # Invoke
//
// Types added to the container may be consumed by using the Invoke method.
// Invoke accepts any function that accepts one or more parameters and
// optionally, returns an error. Dig calls the function with the requested
// type, instantiating only those types that were requested by the function.
// The call fails if any type or its dependencies (both direct and transitive)
// were not available in the container.
//
//	err := c.Invoke(func(l *log.Logger) {
//	  // ...
//	})
//	if err != nil {
//	  // ...
//	}
//
//	err := c.Invoke(func(server *http.Server) error {
//	  // ...
//	})
//	if err != nil {
//	  // ...
//	}
//
// Any error returned by the invoked function is propagated back to the
// caller.
//
// # Parameter Objects
//
// Constructors declare their dependencies as function parameters. This can
// very quickly become unreadable if the constructor has a lot of
// dependencies.
//
//	func NewHandler(users *UserGateway, comments *CommentGateway, posts *PostGateway, votes *VoteGateway, authz *AuthZGateway) *Handler {
//	  // ...
//	}
//
// A pattern employed to improve readability in a situation like this is to
// create a struct that lists all the parameters of the function as fields and
// changing the function to accept that struct instead. This is referred to as
// a parameter object.
//
// Dig has first class support for parameter objects: any struct embedding
// dig.In gets treated as a parameter object. The following is equivalent to
// the constructor above.
//
//	type HandlerParams struct {
//	  dig.In
//
//	  Users    *UserGateway
//	  Comments *CommentGateway
//	  Posts    *PostGateway
//	  Votes    *VoteGateway
//	  AuthZ    *AuthZGateway
//	}
//
//	func NewHandler(p HandlerParams) *Handler {
//	  // ...
//	}
//
// Handlers can receive any combination of parameter objects and parameters.
//
//	func NewHandler(p HandlerParams, l *log.Logger) *Handler {
//	  // ...
//	}
//
// # Result Objects
//
// Result objects are the flip side of parameter objects. These are structs
// that represent multiple outputs from a single function as fields in the
// struct. Structs embedding dig.Out get treated as result objects.
//
//	func SetupGateways(conn *sql.DB) (*UserGateway, *CommentGateway, *PostGateway, error) {
//	  // ...
//	}
//
// The above is equivalent to,
//
//	type Gateways struct {
//	  dig.Out
//
//	  Users    *UserGateway
//	  Comments *CommentGateway
//	  Posts    *PostGateway
//	}
//
//	func SetupGateways(conn *sql.DB) (Gateways, error) {
//	  // ...
//	}
//
// # Optional Dependencies
//
// Constructors often don't have a hard dependency on some types and
// are able to operate in a degraded state when that dependency is missing.
// Dig supports declaring dependencies as optional by adding an
// `optional:"true"` tag to fields of a dig.In struct.
//
// Fields in a dig.In structs that have the `optional:"true"` tag are treated
// as optional by Dig.
//
//	type UserGatewayParams struct {
//	  dig.In
//
//	  Conn  *sql.DB
//	  Cache *redis.Client `optional:"true"`
//	}
//
// If an optional field is not available in the container, the constructor
// will receive a zero value for the field.
//
//	func NewUserGateway(p UserGatewayParams, log *log.Logger) (*UserGateway, error) {
//	  if p.Cache == nil {
//	    log.Print("Caching disabled")
//	  }
//	  // ...
//	}
//
// Constructors that declare dependencies as optional MUST handle the case of
// those dependencies being absent.
//
// The optional tag also allows adding new dependencies without breaking
// existing consumers of the constructor.
//
// # Named Values
//
// Some use cases call for multiple values of the same type. Dig allows adding
// multiple values of the same type to the container with the use of Named
// Values.
//
// Named Values can be produced by passing the dig.Name option when a
// constructor is provided. All values produced by that constructor will have
// the given name.
//
// Given the following constructors,
//
//	func NewReadOnlyConnection(...) (*sql.DB, error)
//	func NewReadWriteConnection(...) (*sql.DB, error)
//
// You can provide *sql.DB into a Container under different names by passing
// the dig.Name option.
//
//	c.Provide(NewReadOnlyConnection, dig.Name("ro"))
//	c.Provide(NewReadWriteConnection, dig.Name("rw"))
//
// Alternatively, you can produce a dig.Out struct and tag its fields with
// `name:".."` to have the corresponding value added to the graph under the
// specified name.
//
//	type ConnectionResult struct {
//	  dig.Out
//
//	  ReadWrite *sql.DB `name:"rw"`
//	  ReadOnly  *sql.DB `name:"ro"`
//	}
//
//	func ConnectToDatabase(...) (ConnectionResult, error) {
//	  // ...
//	  return ConnectionResult{ReadWrite: rw, ReadOnly:  ro}, nil
//	}
//
// Regardless of how a Named Value was produced, it can be consumed by another
// constructor by accepting a dig.In struct which has exported fields with the
// same name AND type that you provided.
//
//	type GatewayParams struct {
//	  dig.In
//
//	  WriteToConn  *sql.DB `name:"rw"`
//	  ReadFromConn *sql.DB `name:"ro"`
//	}
//
// The name tag may be combined with the optional tag to declare the
// dependency optional.
//
//	type GatewayParams struct {
//	  dig.In
//
//	  WriteToConn  *sql.DB `name:"rw"`
//	  ReadFromConn *sql.DB `name:"ro" optional:"true"`
//	}
//
//	func NewCommentGateway(p GatewayParams, log *log.Logger) (*CommentGateway, error) {
//	  if p.ReadFromConn == nil {
//	    log.Print("Warning: Using RW connection for reads")
//	    p.ReadFromConn = p.WriteToConn
//	  }
//	  // ...
//	}
//
// # Value Groups
//
// Added in Dig 1.2.
//
// Dig provides value groups to allow producing and consuming many values of
// the same type. Value groups allow constructors to send values to a named,
// unordered collection in the container. Other constructors can request all
// values in this collection as a slice.
//
// Constructors can send values into value groups by returning a dig.Out
// struct tagged with `group:".."`.
//
//	type HandlerResult struct {
//	  dig.Out
//
//	  Handler Handler `group:"server"`
//	}
//
//	func NewHelloHandler() HandlerResult {
//	  ..
//	}
//
//	func NewEchoHandler() HandlerResult {
//	  ..
//	}
//
// Any number of constructors may provide values to this named collection.
// Other constructors can request all values for this collection by requesting
// a slice tagged with `group:".."`. This will execute all constructors that
// provide a value to that group in an unspecified order.
//
//	type ServerParams struct {
//	  dig.In
//
//	  Handlers []Handler `group:"server"`
//	}
//
//	func NewServer(p ServerParams) *Server {
//	  server := newServer()
//	  for _, h := range p.Handlers {
//	    server.Register(h)
//	  }
//	  return server
//	}
//
// Note that values in a value group are unordered. Dig makes no guarantees
// about the order in which these values will be produced.
//
// Value groups can be used to provide multiple values for a group from a
// dig.Out using slices, however considering groups are retrieved by requesting
// a slice this implies that the values must be retrieved using a slice of
// slices. As of dig v1.9.0, if you want to provide individual elements to the
// group instead of the slice itself, you can add the `flatten` modifier to the
// group from a dig.Out.
//
//	type IntResult struct {
//	  dig.Out
//
//	  Handler []int `group:"server"`         // [][]int from dig.In
//	  Handler []int `group:"server,flatten"` // []int from dig.In
//	}
package dig // import "go.uber.org/dig"
