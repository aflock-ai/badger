// Command example is the reference connector: one read tool and one write tool against a toy
// item API, written the way the Jira, Confluence and GitLab connectors are. It is not shipped.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"
)

var spec = sdk.Spec{Name: "example", Version: "0.1.0", Scheme: sdk.Bearer, Tools: tools}

func main() { sdk.Main(spec) }

func tools(c *sdk.Client) []sdk.Tool {
	return []sdk.Tool{
		{
			Name:        "example_get_item",
			Description: "Get one item by numeric id: title, state, author and body.",
			InputSchema: sdk.ObjectSchema(map[string]string{"id": "integer"}, "id"),
			Handler: func(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
				var a struct {
					ID int `json:"id"`
				}
				if err := sdk.Decode(args, &a); err != nil {
					return sdk.Result{}, err
				}
				b, err := c.Get(ctx, fmt.Sprintf("/items/%d", a.ID), nil)
				if err != nil {
					return sdk.Result{}, err
				}
				var it struct {
					ID                         int
					Title, State, Author, Body string
				}
				if err := json.Unmarshal(b, &it); err != nil {
					return sdk.Result{}, fmt.Errorf("unexpected response from the service")
				}
				return sdk.Result{Text: fmt.Sprintf("# %d: %s\nstate: %s, author: %s\n\n%s", it.ID, it.Title, it.State, it.Author, it.Body)}, nil
			},
		},
		{
			Name:        "example_add_note",
			Description: "Add a note to an item. Changes the service.",
			Write:       true,
			InputSchema: sdk.ObjectSchema(map[string]string{"id": "integer", "text": "string"}, "id", "text"),
			Handler: func(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
				var a struct {
					ID   int    `json:"id"`
					Text string `json:"text"`
				}
				if err := sdk.Decode(args, &a); err != nil {
					return sdk.Result{}, err
				}
				body, _ := json.Marshal(map[string]string{"body": a.Text})
				if _, err := c.Do(ctx, http.MethodPost, "/items/"+url.PathEscape(fmt.Sprint(a.ID))+"/notes", nil, "application/json", body); err != nil {
					return sdk.Result{}, err
				}
				return sdk.Result{Text: fmt.Sprintf("note added to item %d", a.ID)}, nil
			},
		},
	}
}
