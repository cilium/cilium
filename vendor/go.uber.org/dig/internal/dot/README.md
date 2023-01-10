# Dot

The dot module generates a DOT file representation of a dependency graph.

## Interpreting the graph

The graph should be read from left to right. The leftmost node in the graph (the root node) depends
on its dependency tree to the right. An arrow from node_a to node_b in the graph means that node_b
is consumed by node_a and that node_b is a parameter of node_a. The rendered graph holds the
following kinds of nodes,

**Nodes:**

- *Constructors* [Rectangles]: Takes parameters and produces results.
- *Results* [Ovals]: Results inside a constructor are produced by that constructor. Results are consumed
directly by other constructors and/or part of a group of results.
- *Groups* [Diamonds]: Represent value groups in [fx](https://godoc.org/go.uber.org/fx). Multiple results can form a group. Any
result linked to a group by an edge are members of that group. A group is a collection of results.
Groups can also be parameters of constructors.

**Edges:**

- *Solid Arrows*: An arrow from node_a to node_b means that node_b is a parameter of node_a and that
node_a depends on node_b.
- *Dashed Arrows*: A dashed arrow from node_a to node_b represents an optional dependency that node_a
has on node_b.

**Graph Colors:**

- *Red*: Graph nodes are the root cause failures.
- *Orange*: Graph nodes are the transitive failures.

## Testing and verifying changes

Unit tests and visualize golden tests are run with

```shell
$ make test
```

You can visualize the effect of your code changes by visualizing generated test graphs as pngs.

In the dig root directory, generate the graph DOT files with respect to your latest code changes.

```shell
$ go test -generate
```

Assuming that you have [graphviz](https://www.graphviz.org/) installed and are in the testdata directory,
generate a png image representation of a graph for viewing.

```shell
$ dot -Tpng ${name_of_dot_file_in_testdata}.dot -o ${name_of_dot_file_in_testdata}.png
$ open ${name_of_dot_file_in_testdata}.png
```

## Graph Pruning

If dot.Visualize is used to visualize an error graph, non-failing nodes are pruned out of the graph
to make the error graph more readable to the user. Pruning increases readability since successful
nodes clutter the graph and do not help the user debug errors.
