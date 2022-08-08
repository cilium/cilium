/*
multistep is a Go library for building up complex actions using discrete,
individual "steps." These steps are strung together and run in sequence
to achieve a more complex goal. The runner handles cleanup, cancelling, etc.
if necessary.

## Basic Example

Make a step to perform some action. The step can access your "state",
which is passed between steps by the runner.

```go
type stepAdd struct{}

func (s *stepAdd) Run(ctx context.Context, state multistep.StateBag) multistep.StepAction {
    // Read our value and assert that it is they type we want
    value := state.Get("value").(int)
    fmt.Printf("Value is %d\n", value)

    // Store some state back
    state.Put("value", value + 1)
    return multistep.ActionContinue
}

func (s *stepAdd) Cleanup(multistep.StateBag) {
	// This is called after all the steps have run or if the runner is
	// cancelled so that cleanup can be performed.
}
```

Make a runner and call your array of Steps.

```go
func main() {
    // Our "bag of state" that we read the value from
    state := new(multistep.BasicStateBag)
    state.Put("value", 0)

    steps := []multistep.Step{
        &stepAdd{},
        &stepAdd{},
        &stepAdd{},
    }

    runner := &multistep.BasicRunner{Steps: steps}

    // Executes the steps
    runner.Run(context.Background(), state)
}
```

This will produce:

```
Value is 0
Value is 1
Value is 2
```
*/
package multistep
