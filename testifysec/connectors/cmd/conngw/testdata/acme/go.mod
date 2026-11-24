module example.com/acme-connector

go 1.26.4

require github.com/aflock-ai/badger/testifysec/connectors v0.0.0

// A plugin built outside the connectors module: it imports only the public sdk package. A vendor
// build requires a released version; the end-to-end test points it at this checkout.
replace github.com/aflock-ai/badger/testifysec/connectors => ../../../..
