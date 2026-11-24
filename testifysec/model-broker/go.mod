module github.com/aflock-ai/badger/testifysec/model-broker

go 1.26.4

require (
	github.com/lib/pq v1.12.3
	github.com/aflock-ai/badger/testifysec/connectors v0.0.0
)

// The marking parser and dominance rule come from this repository's connectors.
replace github.com/aflock-ai/badger/testifysec/connectors => ../connectors
