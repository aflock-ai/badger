// Command jira is Badger's Jira Data Center/Server connector: REST API v2 with a personal access
// token sent as Authorization: Bearer. See testifysec/CONNECTORS.md for the shared rules.
//
// Read tools: jira_search, jira_get_issue, jira_list_comments. Write tools, registered only with
// --enable-writes: jira_add_comment, jira_create_issue, jira_transition_issue.
//
// Classification. A Jira instance holds one classification: every result carries the
// connector's administrator-set marking, and the connector reads nothing about classification
// from Jira (fields, labels, descriptions, comments).
package main

import (
	"github.com/aflock-ai/badger/testifysec/connectors/sdk"
)

var spec = sdk.Spec{Name: "jira", Version: "0.1.0", Scheme: sdk.Bearer,
	Tools: func(c *sdk.Client) []sdk.Tool { return tools(&jira{c: c}) }}

func main() { sdk.Main(spec) }
