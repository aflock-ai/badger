package broker

import (
	"testing"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

// unreadableLedger makes every read of the usage ledger fail, as a database outage would.
func unreadableLedger(t *testing.T, f *fixture) {
	t.Helper()
	f.pg.Super(t, `REVOKE SELECT ON broker.usage_calls FROM `+pgtest.Service)
}

// A ledger that cannot be read is reported as unavailable, never as no usage: the usage reports
// (a person's, the admin's) and the quota page's spend answer 503 instead of zeros.
func TestUsageReportsRefuseAnUnreadableLedger(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	if code := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":1}}`); code != 200 {
		t.Fatal(code)
	}
	if code, _ := pipelineCall(f); code != 200 {
		t.Fatal(code)
	}
	unreadableLedger(t, f)
	for name, c := range map[string]struct {
		h func() int
	}{
		"person's usage": {func() int {
			return do(f.edge, "GET", "/v1/usage", map[string]string{"x-broker-principal": "alice@example.com"}, "").Code
		}},
		"admin usage": {func() int { return do(f.admin, "GET", "/admin/v1/usage", admin("u1"), "").Code }},
		"quota spend": {func() int { return do(f.admin, "GET", "/admin/v1/quotas", admin("u1"), "").Code }},
	} {
		if code := c.h(); code != 503 {
			t.Errorf("%s with an unreadable ledger: %d, want 503", name, code)
		}
	}
}

// Enforcement fails closed on the same outage: a limited principal's call is refused rather than
// let through on spend read as zero.
func TestQuotaRefusesWhenTheLedgerCannotBeRead(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	if code := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":1}}`); code != 200 {
		t.Fatal(code)
	}
	unreadableLedger(t, f)
	if code, _ := pipelineCall(f); code != 503 {
		t.Fatalf("a limited call with an unreadable ledger: %d, want 503", code)
	}
}

// must is b, or a panic on err: a report the test expects to read.
func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
