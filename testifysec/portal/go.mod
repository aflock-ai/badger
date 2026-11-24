module github.com/aflock-ai/badger/testifysec/portal

go 1.26.4

require (
	github.com/aflock-ai/rookery/attestation v0.1.0
	github.com/lib/pq v1.12.3
	github.com/aflock-ai/badger/testifysec/connectors v0.0.0
	github.com/aflock-ai/badger/testifysec/model-broker v0.0.0
)

// The service command builds the broker from this repository.
replace github.com/aflock-ai/badger/testifysec/model-broker => ../model-broker

// The broker's marking package comes from this repository's connectors.
replace github.com/aflock-ai/badger/testifysec/connectors => ../connectors

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20250730155240-ffadbf3f398c // indirect
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea // indirect
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.step.sm/crypto v0.81.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
