package multistep

// if returns step only if on is true.
func If(on bool, step Step) Step {
	if on == false {
		return &nullStep{}
	}
	return step
}
