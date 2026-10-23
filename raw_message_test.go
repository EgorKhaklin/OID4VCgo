package oid4vci_test

import (
	"bufio"
	"bytes"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRawMessagesDecodeStrictly: a json.RawMessage holds part of a
// document that strictjson.Unmarshal checked for duplicate members, but
// its member names can only be checked against the type it's decoded
// into, so encoding/json.Unmarshal mustn't decode one: it would take
// {"nonce": "a", "Nonce": "b"} as "b". Decode it with strictjson.
// The packages in strictPackages decode nothing with encoding/json.
func TestRawMessagesDecodeStrictly(t *testing.T) {
	if testing.Short() {
		t.Skip("type-checks the module")
	}
	exports := exportData(t)
	out, err := exec.Command("go", "list", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \"\\t\"}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := exports[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return os.Open(file)
	})
	jsonPkg, err := imp.Import("encoding/json")
	if err != nil {
		t.Fatal(err)
	}
	// RawMessage is an alias in some Go releases: compare the type it
	// names.
	raw := types.Unalias(jsonPkg.Scope().Lookup("RawMessage").Type())
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 3 {
			continue
		}
		checkRawMessageDecodes(t, fset, imp, raw, fields[0], fields[1], fields[2:])
	}
}

// exportData maps each package the module's packages depend on to its
// compiled export data.
func exportData(t *testing.T) map[string]string {
	t.Helper()
	out, err := exec.Command("go", "list", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list -export: %v", err)
	}
	exports := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if path, file, ok := strings.Cut(scanner.Text(), "\t"); ok && file != "" {
			exports[path] = file
		}
	}
	return exports
}

// strictPackages decode JSON only from the parties they talk to — a
// wallet's from Credential Issuers, Authorization Servers and
// Verifiers — so all of it with strictjson, which refuses what
// parsers disagree on.
var strictPackages = map[string]bool{
	"github.com/idfoundry/oid4vcgo/wallet": true,
}

func checkRawMessageDecodes(t *testing.T, fset *token.FileSet, imp types.Importer, raw types.Type, path, dir string, names []string) {
	t.Helper()
	files := make([]*ast.File, 0, len(names))
	for _, name := range names {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
	if _, err := (&types.Config{Importer: imp}).Check(path, fset, files, info); err != nil {
		t.Fatalf("type-check %s: %v", path, err)
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if strictPackages[path] && (isJSONFunc(info, call.Fun, "Unmarshal") || isJSONFunc(info, call.Fun, "NewDecoder")) {
				t.Errorf("%s: %s decodes with encoding/json: use strictjson.Unmarshal", fset.Position(call.Pos()), path)
				return true
			}
			if !isJSONFunc(info, call.Fun, "Unmarshal") {
				return true
			}
			if isRawMessage(info, raw, call.Args[0]) {
				t.Errorf("%s: encoding/json.Unmarshal decodes a json.RawMessage: use strictjson.Unmarshal", fset.Position(call.Pos()))
			}
			return true
		})
	}
}

// isJSONFunc reports whether fun is encoding/json's function name.
func isJSONFunc(info *types.Info, fun ast.Expr, name string) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj, ok := info.Uses[sel.Sel].(*types.Func)
	return ok && obj.Pkg() != nil && obj.Pkg().Path() == "encoding/json" && obj.Name() == name
}

// isRawMessage reports whether arg is a json.RawMessage, possibly
// converted to []byte.
func isRawMessage(info *types.Info, raw types.Type, arg ast.Expr) bool {
	for {
		arg = ast.Unparen(arg)
		if typ := info.Types[arg].Type; typ != nil && types.Identical(types.Unalias(typ), raw) {
			return true
		}
		conv, ok := arg.(*ast.CallExpr)
		if !ok || len(conv.Args) != 1 || !info.Types[conv.Fun].IsType() {
			return false
		}
		arg = conv.Args[0]
	}
}
