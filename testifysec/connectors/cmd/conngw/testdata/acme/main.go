// Command acme stands in for a proprietary connector plugin built outside this module. It imports
// only the public sdk package. The gateway admits it by digest and decides its marking and who may
// call which tool; nothing here can change either.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"
)

var spec = sdk.Spec{Name: "acme", Version: "0.1.0", Scheme: sdk.Bearer, Tools: tools}

func main() { sdk.Main(spec) }

func tools(c *sdk.Client) []sdk.Tool {
	return []sdk.Tool{
		{
			Name:        "acme_echo",
			Description: "Echo text back, upper-cased. Reads nothing from the service.",
			InputSchema: sdk.ObjectSchema(map[string]string{"text": "string"}, "text"),
			Handler: func(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
				var a struct {
					Text string `json:"text"`
				}
				if err := sdk.Decode(args, &a); err != nil {
					return sdk.Result{}, err
				}
				return sdk.Result{Text: "echo: " + strings.ToUpper(a.Text)}, nil
			},
		},
		{
			Name:        "acme_get_ticket",
			Description: "Read a ticket from the service.",
			InputSchema: sdk.ObjectSchema(map[string]string{"id": "integer"}, "id"),
			Handler: func(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
				var a struct {
					ID int `json:"id"`
				}
				if err := sdk.Decode(args, &a); err != nil {
					return sdk.Result{}, err
				}
				b, err := c.Get(ctx, fmt.Sprintf("/tickets/%d", a.ID), nil)
				if err != nil {
					return sdk.Result{}, err
				}
				return sdk.Result{Text: string(b)}, nil
			},
		},
		{
			Name:        "acme_close_ticket",
			Description: "Close a ticket. Changes the service.",
			Write:       true,
			InputSchema: sdk.ObjectSchema(map[string]string{"id": "integer"}, "id"),
			Handler: func(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
				var a struct {
					ID int `json:"id"`
				}
				if err := sdk.Decode(args, &a); err != nil {
					return sdk.Result{}, err
				}
				if _, err := c.Do(ctx, "POST", fmt.Sprintf("/tickets/%d/close", a.ID), url.Values{}, "application/json", []byte("{}")); err != nil {
					return sdk.Result{}, err
				}
				return sdk.Result{Text: fmt.Sprintf("closed %d", a.ID)}, nil
			},
		},
	}
}
