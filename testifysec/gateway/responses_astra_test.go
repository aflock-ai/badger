// jade:ring local
package main

import (
	"fmt"
	"testing"
)

func TestResponsesAstraReasoningContract(t *testing.T) {
	for _, tc := range []struct {
		name, model, extra string
		accepted           bool
	}{
		{"default", "gpt-6-astra", ``, true},
		{"low", "gpt-6-astra", `,"reasoning":{"effort":"low"}`, true},
		{"medium", "gpt-6-astra", `,"reasoning":{"effort":"medium"}`, true},
		{"high", "gpt-6-astra", `,"reasoning":{"effort":"high"}`, true},
		{"xhigh", "gpt-6-astra", `,"reasoning":{"effort":"xhigh"}`, true},
		{"max", "gpt-6-astra", `,"reasoning":{"effort":"max","summary":"auto"}`, true},
		{"escaped-value", "gpt-6-astra", `,"reasoning":{"effort":"\u006dax"}`, true},
		{"none", "gpt-6-astra", `,"reasoning":{"effort":"none"}`, false},
		{"minimal", "gpt-6-astra", `,"reasoning":{"effort":"minimal"}`, false},
		{"unknown", "gpt-6-astra", `,"reasoning":{"effort":"ultra"}`, false},
		{"case", "gpt-6-astra", `,"reasoning":{"effort":"MAX"}`, false},
		{"null", "gpt-6-astra", `,"reasoning":{"effort":null}`, false},
		{"object", "gpt-6-astra", `,"reasoning":{"effort":{"level":"max"}}`, false},
		{"field-alias", "gpt-6-astra", `,"reasoning":{"Effort":"max"}`, false},
		{"duplicate", "gpt-6-astra", `,"reasoning":{"effort":"max","effort":"low"}`, false},
		{"escaped-duplicate", "gpt-6-astra", `,"reasoning":{"effort":"max","\u0065ffort":"low"}`, false},
		{"temperature", "gpt-6-astra", `,"reasoning":{"effort":"max"},"temperature":1`, false},
		{"top-p", "gpt-6-astra", `,"reasoning":{"effort":"max"},"top_p":1`, false},
		{"stored-reference", "gpt-6-astra", `,"reasoning":{"effort":"max"},"previous_response_id":"stored"`, false},
		{"extra-context", "gpt-6-astra", `,"reasoning":{"effort":"max","context":"stored"}`, false},
		{"other-model-max", "gpt-5.4", `,"reasoning":{"effort":"max"}`, false},
		{"prefix-not-approved", "gpt-6-astra-unreviewed", `,"reasoning":{"effort":"max"}`, false},
		{"other-model-none", "gpt-5.4", `,"reasoning":{"effort":"none"}`, true},
		{"other-model-minimal", "gpt-5.4", `,"reasoning":{"effort":"minimal"}`, true},
		{"other-model-temperature", "gpt-5.4", `,"temperature":1,"top_p":1`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{"model":%q,"store":false,"input":"synthetic"%s}`, tc.model, tc.extra)
			var body jsonObject
			err := strictJSON([]byte(raw), &body)
			if err == nil {
				err = validateResponsesRequest(body)
			}
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v, want=%v (%v)", err == nil, tc.accepted, err)
			}
		})
	}
}
