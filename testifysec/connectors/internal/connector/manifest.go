package connector

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
)

// Manifest describes the binary for a plugin bundle: its name, version and every tool, write tools
// marked. It is built without a client, so a spec's Tools function must only capture the client, not
// call it. The digest is left empty: the packer adds the executable's.
func Manifest(spec Spec) ([]byte, error) {
	m := bundle.Manifest{Schema: 1, Name: spec.Name, Version: spec.Version, Tools: []bundle.Tool{}}
	for _, t := range spec.Tools(nil) {
		if !toolName.MatchString(t.Name) || t.Description == "" || t.Handler == nil {
			return nil, fmt.Errorf("tool %q: needs a lower_snake name, a description and a handler", t.Name)
		}
		schema := t.InputSchema
		if schema == nil {
			schema = ObjectSchema(nil)
		}
		m.Tools = append(m.Tools, bundle.Tool{Name: t.Name, Description: t.Description, Write: t.Write, InputSchema: schema})
	}
	sort.Slice(m.Tools, func(i, j int) bool { return m.Tools[i].Name < m.Tools[j].Name })
	return json.MarshalIndent(m, "", "  ")
}
