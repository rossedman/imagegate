// Package gofiles walks the Go source files named by package patterns, for
// the repo's check tools (doccheck, generated). It needs no build: files are
// parsed one by one with go/parser.
package gofiles

import (
	"bufio"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// File is one parsed, non-test Go source file.
type File struct {
	// Path is the file's path as walked, slash-separated.
	Path string
	// Dir is the directory holding the file, slash-separated.
	Dir string
	// AST is the parsed file, with comments.
	AST *ast.File
	// Fset positions AST.
	Fset *token.FileSet
	// Generated is true for files with a "Code generated ... DO NOT EDIT."
	// header.
	Generated bool
}

// skipDir reports directories the go tool ignores, plus build and docs
// output that may hold copied sources.
func skipDir(name string) bool {
	switch name {
	case "testdata", "vendor", "node_modules", "site", "dist":
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// Walk parses every non-test .go file under the given patterns, in path
// order. A pattern is a directory ("./internal/verify") or a directory
// followed by "/..." for it and everything below it. No patterns means ".".
func Walk(patterns []string) ([]File, error) {
	if len(patterns) == 0 {
		patterns = []string{"."}
	}
	seen := map[string]bool{}
	var out []File
	for _, pat := range patterns {
		root, recursive := strings.CutSuffix(pat, "...")
		root = filepath.Clean(strings.TrimSuffix(root, "/"))
		if root == "" {
			root = "."
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path == root {
					return nil
				}
				if !recursive || skipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || seen[path] {
				return nil
			}
			seen[path] = true
			f, err := parse(path)
			if err != nil {
				return err
			}
			out = append(out, f)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// parse reads and parses one file.
func parse(path string) (File, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return File{}, err
	}
	p := filepath.ToSlash(path)
	return File{Path: p, Dir: filepath.ToSlash(filepath.Dir(path)), AST: f, Fset: fset, Generated: ast.IsGenerated(f)}, nil
}

// ModulePath returns the module path declared in the go.mod at gomod.
func ModulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if mod, ok := strings.CutPrefix(strings.TrimSpace(s.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(mod), `"`), nil
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", errors.New(gomod + ": no module directive")
}

// ImportPath is the import-path-qualified name of a file at path relative to
// the module root, as it appears in coverage profiles.
func ImportPath(module, path string) string {
	p := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(path)), "./")
	return fmt.Sprintf("%s/%s", module, p)
}
