module github.com/aflock-ai/badger/testifysec/gateway

go 1.26.4

require (
	github.com/aflock-ai/badger/testifysec/connectors v0.0.0
	github.com/aflock-ai/badger/testifysec/platform v0.0.0
)

replace github.com/aflock-ai/badger/testifysec/connectors => ../connectors

replace github.com/aflock-ai/badger/testifysec/platform => ../platform
