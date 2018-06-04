package main

import "github.com/lyft/protoc-gen-star"

func main() {
	pgs.
		Init(pgs.DebugEnv("DEBUG_PGV")).
		RegisterModule(Validator()).
		RegisterPostProcessor(pgs.GoFmt()).
		Render()
}
