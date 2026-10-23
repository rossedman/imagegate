// Command doccheck fails when a function or method has no doc comment, or a
// package has no package comment. Test files and generated files are
// skipped.
//
//	go run ./tools/doccheck ./...
package main

import (
	"fmt"
	"go/ast"
	"io"
	"os"
	"sort"

	"github.com/rossedman/imagegate/tools/internal/gofiles"
)

// main runs the check on the patterns in os.Args.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run checks the files under patterns, printing one line per problem to
// stdout. It returns 0 when there are none, 1 when there are, and 2 when the
// files could not be read.
func run(patterns []string, stdout, stderr io.Writer) int {
	files, err := gofiles.Walk(patterns)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "doccheck:", err)
		return 2
	}
	problems := check(files)
	for _, p := range problems {
		_, _ = fmt.Fprintln(stdout, p)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(stdout, "doccheck: %d problem(s)\n", len(problems))
		return 1
	}
	return 0
}

// check returns every function or method without a doc comment, then every
// package directory where no file has a package comment.
func check(files []gofiles.File) []string {
	var out []string
	hasPkgDoc := map[string]bool{}
	for _, f := range files {
		if f.Generated {
			continue
		}
		if _, ok := hasPkgDoc[f.Dir]; !ok {
			hasPkgDoc[f.Dir] = false
		}
		if f.AST.Doc != nil {
			hasPkgDoc[f.Dir] = true
		}
		for _, d := range f.AST.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Doc != nil {
				continue
			}
			out = append(out, fmt.Sprintf("%s: %s has no doc comment", f.Fset.Position(fd.Pos()), funcName(fd)))
		}
	}
	var dirs []string
	for dir, ok := range hasPkgDoc {
		if !ok {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		out = append(out, dir+": package has no package comment")
	}
	return out
}

// funcName is fd's name, qualified with its receiver type for methods.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	switch x := t.(type) {
	case *ast.IndexExpr:
		t = x.X
	case *ast.IndexListExpr:
		t = x.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}
