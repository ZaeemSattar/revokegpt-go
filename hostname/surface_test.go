package hostname

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestThePublicSurface pins the exported names of the package (the SDK and the firewall share it).
func TestThePublicSurface(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	var got []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.IsExported() {
				got = append(got, fn.Name.Name)
			}
		}
	}
	sort.Strings(got)
	if want := "Canonicalize HostMatches IsValidPattern Matches RequestHost"; strings.Join(got, " ") != want {
		t.Fatalf("exported %v, want %s", got, want)
	}
}
