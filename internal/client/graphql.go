package client

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GraphQLError is one entry of a GraphQL response's errors array.
type GraphQLError struct {
	Message string `json:"message"`
}

type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []GraphQLError  `json:"errors"`
}

// graphqlEndpoint is the BFF's GraphQL door. The public spelling is <slug>.authfi.io/graphql (non-prod:
// <slug>.np.authfi.io/graphql), so it is derived from the tenant slug unless GraphQLURL is set.
func (c *Client) graphqlEndpoint() string {
	if c.GraphQLURL != "" {
		return c.GraphQLURL
	}
	return fmt.Sprintf("https://%s.authfi.io/graphql", c.Tenant)
}

// graphql runs one operation against the BFF and decodes its data into out. A non-200 status and any entry in
// errors are failures: a partial answer is never returned as a value.
func (c *Client) graphql(query string, vars map[string]any, out any) error {
	body, status, err := c.do("POST", c.graphqlEndpoint(), graphQLRequest{Query: query, Variables: vars})
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("graphql: %s (status %d)", strings.TrimSpace(string(body)), status)
	}
	var resp graphQLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode graphql response: %w", err)
	}
	if len(resp.Errors) > 0 {
		msgs := make([]string, 0, len(resp.Errors))
		for _, e := range resp.Errors {
			msgs = append(msgs, e.Message)
		}
		return fmt.Errorf("%s", strings.Join(msgs, "; "))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(resp.Data, out); err != nil {
		return fmt.Errorf("decode graphql data: %w", err)
	}
	return nil
}
