// Command configref lists every field a component's JSON configuration decodes into, read from the
// Go source: key, type, default, comment and the line it is declared on. The docs generator runs it
// to build the configuration reference and the docs MCP server's get_config_reference.
//
//	configref <repo> <component>=<dir>#<Type>[@<prefix>] ...
//
// <dir> is a package directory relative to <repo>. Nested struct types of the same package are
// expanded in place; a prefix puts a second type under a key of the first (a section the command
// decodes on its own). Defaults are the ones the source states in the field's comment ("default
// 64", "absent: 30"); a default that only the loader's code knows is not seen here.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

type Field struct {
	Key      string `json:"key"`
	Type     string `json:"type"`
	Optional bool   `json:"optional"`
	Default  string `json:"default"`
	Doc      string `json:"doc"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Symbol   string `json:"symbol"`
}

type Component struct {
	Component string  `json:"component"`
	Fields    []Field `json:"fields"`
}

var spec = regexp.MustCompile(`^([a-z][a-z0-9.-]*)=([A-Za-z0-9_./-]+)#([A-Za-z_]\w*)(?:@([a-z][a-z0-9_.-]*))?$`)

// The default a comment states: "default 64", "defaults to 30", "absent: 30".
var stated = regexp.MustCompile(`(?i)\b(?:defaults? (?:to |is )?|absent: ?)([^\s;,)]+?)[.;,)]?(?:\s|$)`)

type pkg struct {
	fset  *token.FileSet
	types map[string]*ast.TypeSpec
	files map[string]string // type name -> file, relative to the repo
	// custom are the types with their own UnmarshalJSON: their JSON form is not their fields.
	custom map[string]bool
}

func load(repo, dir string) (*pkg, error) {
	p := &pkg{fset: token.NewFileSet(), types: map[string]*ast.TypeSpec{}, files: map[string]string{}, custom: map[string]bool{}}
	names, err := filepath.Glob(filepath.Join(repo, dir, "*.go"))
	if err != nil || len(names) == 0 {
		return nil, fmt.Errorf("no Go files in %s", dir)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(p.fset, name, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(repo, name)
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "UnmarshalJSON" {
				if id, ok := elemIdent(fn.Recv.List[0].Type); ok {
					p.custom[id] = true
				}
				continue
			}
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.TYPE {
				continue
			}
			for _, s := range g.Specs {
				t := s.(*ast.TypeSpec)
				p.types[t.Name.Name] = t
				p.files[t.Name.Name] = filepath.ToSlash(rel)
			}
		}
	}
	return p, nil
}

func text(groups ...*ast.CommentGroup) string {
	var parts []string
	for _, g := range groups {
		if g != nil {
			if s := strings.Join(strings.Fields(g.Text()), " "); s != "" {
				parts = append(parts, s)
			}
		}
	}
	return strings.Join(parts, " ")
}

// The struct a field's type leads to, through pointers, slices, arrays and map values, and the key
// suffix that path adds ("[]" for a list, ".*" for a map value).
func elem(e ast.Expr) (ast.Expr, string) {
	switch t := e.(type) {
	case *ast.StarExpr:
		return elem(t.X)
	case *ast.ArrayType:
		x, s := elem(t.Elt)
		return x, "[]" + s
	case *ast.MapType:
		x, s := elem(t.Value)
		return x, ".*" + s
	}
	return e, ""
}

func (p *pkg) walk(owner string, st *ast.StructType, prefix, file string, seen map[string]bool, out *[]Field) {
	for _, f := range st.Fields.List {
		tag := ""
		if f.Tag != nil {
			tag = reflect.StructTag(strings.Trim(f.Tag.Value, "`")).Get("json")
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" && opts == "" {
			continue
		}
		names := f.Names
		if len(names) == 0 {
			// Embedded. Untagged, a struct's fields are promoted; tagged, it is a field under its
			// key, named by its type, as encoding/json reads it.
			id, ok := elemIdent(f.Type)
			if !ok {
				continue
			}
			if ts := p.types[id]; ts != nil && name == "" {
				if s, isStruct := ts.Type.(*ast.StructType); isStruct {
					if !seen[id] {
						p.walk(id, s, prefix, p.files[id], with(seen, id), out)
					}
					continue
				}
			}
			if name == "" && !ast.IsExported(id) {
				continue // an unexported non-struct is not decoded
			}
			names = []*ast.Ident{{Name: id, NamePos: f.Type.Pos()}}
		}
		for _, n := range names {
			if !n.IsExported() {
				continue
			}
			key := name
			if key == "" {
				key = n.Name
			}
			doc := text(f.Doc, f.Comment)
			def := ""
			if m := stated.FindStringSubmatch(doc); m != nil {
				def = m[1]
			}
			typ := types.ExprString(f.Type)
			if _, ok := f.Type.(*ast.StructType); ok {
				typ = "struct"
			}
			symbol := owner + "." + n.Name
			*out = append(*out, Field{Key: prefix + key, Type: typ, Optional: strings.Contains(opts, "omitempty"), Default: def, Doc: doc, File: file, Line: p.fset.Position(n.Pos()).Line, Symbol: symbol})
			x, suffix := elem(f.Type)
			switch t := x.(type) {
			case *ast.StructType:
				before := len(*out)
				p.walk(owner, t, prefix+key+suffix+".", file, seen, out)
				for i := before; i < len(*out); i++ {
					// An anonymous struct's own fields are cited by the field that holds it; fields
					// of named types inside it keep their own symbol.
					if strings.HasPrefix((*out)[i].Symbol, owner+".") {
						(*out)[i].Symbol = symbol
					}
				}
			case *ast.Ident:
				if named := p.types[t.Name]; named != nil && !seen[t.Name] && !p.custom[t.Name] {
					if s, ok := named.Type.(*ast.StructType); ok {
						p.walk(t.Name, s, prefix+key+suffix+".", p.files[t.Name], with(seen, t.Name), out)
					}
				}
			}
		}
	}
}

func elemIdent(e ast.Expr) (string, bool) {
	x, _ := elem(e)
	id, ok := x.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

func with(seen map[string]bool, name string) map[string]bool {
	next := map[string]bool{name: true}
	for k := range seen {
		next[k] = true
	}
	return next
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: configref <repo> <component>=<dir>#<Type>[@<prefix>] ...")
		os.Exit(2)
	}
	repo := os.Args[1]
	var out []Component
	index := map[string]int{}
	for _, arg := range os.Args[2:] {
		m := spec.FindStringSubmatch(arg)
		if m == nil {
			fmt.Fprintf(os.Stderr, "configref: not <component>=<dir>#<Type>[@<prefix>]: %q\n", arg)
			os.Exit(2)
		}
		component, dir, typ, prefix := m[1], m[2], m[3], m[4]
		p, err := load(repo, dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "configref: %s: %v\n", component, err)
			os.Exit(1)
		}
		t := p.types[typ]
		st, ok := (*ast.StructType)(nil), false
		if t != nil {
			st, ok = t.Type.(*ast.StructType)
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "configref: %s: no struct type %s in %s\n", component, typ, dir)
			os.Exit(1)
		}
		if prefix != "" {
			prefix += "."
		}
		i, ok := index[component]
		if !ok {
			i = len(out)
			index[component] = i
			out = append(out, Component{Component: component, Fields: []Field{}})
		}
		p.walk(typ, st, prefix, p.files[typ], map[string]bool{typ: true}, &out[i].Fields)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		os.Exit(1)
	}
}
