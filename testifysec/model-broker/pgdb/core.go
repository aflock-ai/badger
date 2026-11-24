package pgdb

import _ "embed"

//go:embed core.sql
var coreSQL string

// Core is the label type and the dominance and row-level security functions every marked table
// uses. Migrate it before any component with marked tables.
var Core = Component{Name: "core", Migrations: []Migration{{Version: 1, Name: "labels", SQL: coreSQL}}}
