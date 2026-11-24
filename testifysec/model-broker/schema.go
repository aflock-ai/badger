package broker

import (
	_ "embed"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

//go:embed schema.sql
var schemaSQL string

// Schema is the broker's database component: its tables, with row-level security on the marked
// audit log. Migrate pgdb.Core first.
var Schema = pgdb.Component{Name: "broker", Migrations: []pgdb.Migration{
	{Version: 1, Name: "initial", SQL: schemaSQL + pgdb.Marked("broker.audit")},
}}
