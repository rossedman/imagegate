// Command generated prints the import-path-qualified names of generated Go
// files (those with a "Code generated ... DO NOT EDIT." header), one per
// line, so CI can drop them from the coverage profile:
//
//	grep -vFf <(go run ./tools/generated ./...) coverage.out
//
// It must run from the module root.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rossedman/imagegate/tools/internal/gofiles"
)

// main prints generated files under the patterns in os.Args.
func main() {
	os.Exit(run("go.mod", os.Args[1:], os.Stdout, os.Stderr))
}

// run prints each generated file under patterns, qualified with the module
// path from gomod. It returns 0, or 2 when the files could not be read.
func run(gomod string, patterns []string, stdout, stderr io.Writer) int {
	module, err := gofiles.ModulePath(gomod)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "generated:", err)
		return 2
	}
	files, err := gofiles.Walk(patterns)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "generated:", err)
		return 2
	}
	for _, f := range files {
		if f.Generated {
			_, _ = fmt.Fprintln(stdout, gofiles.ImportPath(module, f.Path))
		}
	}
	return 0
}
