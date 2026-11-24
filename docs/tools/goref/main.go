// Command goref is the Go side of docs/tools/generate.ts.
//
// It lists every declaration a docs {{ref path#Symbol}} can name in one Go file,
// read from stdin, using go/parser: top-level funcs, types, vars and consts, methods as Type.Method,
// and struct fields and interface methods as Type.Field. It prints them as one JSON array of
// {"name", "start", "end"} (1-based lines). A file that does not parse is an error on stderr and
// exit status 1, so a citation is never resolved by guessing.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
)

type decl struct {
	Name  string `json:"name"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

func main() {
	src, err := io.ReadAll(os.Stdin)
	if err == nil {
		var out []decl
		out, err = declarations(src)
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(out)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func declarations(src []byte) ([]decl, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	out := []decl{}
	// A node's Pos excludes its doc comment, so a span starts at the line that declares the name.
	// A raw string's End is its physical end even in a CRLF file (BasicLit.ValueEnd, Go 1.26, which
	// go.mod requires), though its Value has the carriage returns removed.
	// Lines are the file's own, never remapped by a //line directive.
	line := func(p token.Pos) int { return fset.PositionFor(p, false).Line }
	add := func(name string, from, to ast.Node) {
		out = append(out, decl{name, line(from.Pos()), line(to.End())})
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				add(d.Name.Name, d, d)
			} else if t := typeName(d.Recv.List[0].Type); t != "" {
				add(t+"."+d.Name.Name, d, d)
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				// Outside a group (var x, type T) the span starts at the keyword; inside one, at the spec.
				var from ast.Node = s
				if !d.Lparen.IsValid() {
					from = d
				}
				switch s := s.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						add(n.Name, from, s)
					}
				case *ast.TypeSpec:
					add(s.Name.Name, from, s)
					var fields *ast.FieldList
					switch t := s.Type.(type) {
					case *ast.StructType:
						fields = t.Fields
					case *ast.InterfaceType:
						fields = t.Methods
					}
					if fields == nil {
						continue
					}
					for _, fl := range fields.List {
						// An embedded field (or interface) is named by its type: *Reader, io.Writer.
						if len(fl.Names) == 0 {
							if t := typeName(fl.Type); t != "" {
								add(s.Name.Name+"."+t, fl, fl)
							}
						}
						for _, n := range fl.Names {
							add(s.Name.Name+"."+n.Name, fl, fl)
						}
					}
				}
			}
		}
	}
	return out, nil
}

// typeName is the name of the type a receiver or embedded field refers to, through pointers,
// packages and type arguments: *T, pkg.T, T[K], (*T). Empty for anything else.
func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.IndexExpr:
		return typeName(t.X)
	case *ast.IndexListExpr:
		return typeName(t.X)
	case *ast.ParenExpr:
		return typeName(t.X)
	}
	return ""
}
