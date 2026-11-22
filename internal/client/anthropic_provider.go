package client

import (
	"fmt"
	"strings"
)

// Keyless Anthropic model provider, through the BFF's registerMcpUpstream, bindMcpUpstreamFederation,
// verifyMcpUpstreamFederation, setMcpUpstreamEnabled and removeMcpUpstream. The model-provider API is not on the
// management REST surface this client otherwise uses; GraphQL is the only door that reaches it.

const (
	TransportAnthropic = "anthropic"
	AuthKindFederated  = "federated"
)

// McpFederation is a keyless provider's trust (what the customer pastes into Anthropic) and the Anthropic ids bound
// to it. An id that is not recorded is nil.
type McpFederation struct {
	ProviderID           string  `json:"providerId"`
	IssuerURL            string  `json:"issuerUrl"`
	DiscoveryURL         string  `json:"discoveryUrl"`
	JWKSURL              string  `json:"jwksUrl"`
	Subject              string  `json:"subject"`
	SubjectPrefix        string  `json:"subjectPrefix"`
	Audience             string  `json:"audience"`
	OAuthScope           string  `json:"oauthScope"`
	TokenLifetimeSeconds int64   `json:"tokenLifetimeSeconds"`
	SubjectScope         string  `json:"subjectScope"`
	Bound                bool    `json:"bound"`
	Enabled              bool    `json:"enabled"`
	OrganizationID       *string `json:"organizationId"`
	FederationRuleID     *string `json:"federationRuleId"`
	ServiceAccountID     *string `json:"serviceAccountId"`
	WorkspaceID          *string `json:"workspaceId"`
}

// McpUpstream is a registered upstream as the gateway lists it; Federation is set for a keyless provider.
type McpUpstream struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Transport  string         `json:"transport"`
	AuthKind   string         `json:"authKind"`
	Enabled    bool           `json:"enabled"`
	Federation *McpFederation `json:"federation"`
}

// FederationVerification is the answer to one real token exchange at Anthropic. Reason is the gateway's closed
// vocabulary and is set only when Verified is false.
type FederationVerification struct {
	Verified bool    `json:"verified"`
	Reason   *string `json:"reason"`
}

// BindFederationInput are the four ids Anthropic's console shows for the rule, service account and workspace.
type BindFederationInput struct {
	OrganizationID   string
	FederationRuleID string
	ServiceAccountID string
	WorkspaceID      string
}

const federationFields = `providerId issuerUrl discoveryUrl jwksUrl subject subjectPrefix audience oauthScope
  tokenLifetimeSeconds subjectScope bound enabled organizationId federationRuleId serviceAccountId workspaceId`

// RegisterAnthropicProvider registers a keyless Anthropic provider: no key and no url (its address is Anthropic's).
// It is stored off, with its ids unbound.
func (c *Client) RegisterAnthropicProvider(name, subjectScope string) (*McpUpstream, error) {
	input := map[string]any{
		"name":      name,
		"url":       "", // non-null in the schema; a keyless provider takes none
		"transport": TransportAnthropic,
		"authKind":  AuthKindFederated,
	}
	if subjectScope != "" {
		input["subjectScope"] = subjectScope
	}
	var data struct {
		Register McpUpstream `json:"registerMcpUpstream"`
	}
	q := `mutation($input: RegisterMcpUpstreamInput!) {
  registerMcpUpstream(input: $input) { id name transport authKind enabled federation { ` + federationFields + ` } }
}`
	if err := c.graphql(q, map[string]any{"input": input}, &data); err != nil {
		return nil, fmt.Errorf("register provider: %w", err)
	}
	return &data.Register, nil
}

// GetMcpUpstream returns the upstream with that name, or nil when none is registered.
func (c *Client) GetMcpUpstream(name string) (*McpUpstream, error) {
	var data struct {
		Upstreams []McpUpstream `json:"mcpUpstreams"`
	}
	q := `query { mcpUpstreams { id name transport authKind enabled federation { ` + federationFields + ` } } }`
	if err := c.graphql(q, nil, &data); err != nil {
		return nil, fmt.Errorf("read provider: %w", err)
	}
	for i := range data.Upstreams {
		if data.Upstreams[i].Name == name {
			return &data.Upstreams[i], nil
		}
	}
	return nil, nil
}

// BindAnthropicFederation stores the four ids. Calling it again replaces them. It calls nothing at Anthropic and does
// not switch the provider on.
func (c *Client) BindAnthropicFederation(name string, in BindFederationInput) (*McpFederation, error) {
	var data struct {
		Bind McpFederation `json:"bindMcpUpstreamFederation"`
	}
	q := `mutation($name: String!, $input: BindMcpFederationInput!) {
  bindMcpUpstreamFederation(name: $name, input: $input) { ` + federationFields + ` }
}`
	vars := map[string]any{"name": name, "input": map[string]any{
		"organizationId":   in.OrganizationID,
		"federationRuleId": in.FederationRuleID,
		"serviceAccountId": in.ServiceAccountID,
		"workspaceId":      in.WorkspaceID,
	}}
	if err := c.graphql(q, vars, &data); err != nil {
		return nil, fmt.Errorf("bind federation: %w", err)
	}
	return &data.Bind, nil
}

// VerifyAnthropicFederation makes one real exchange at Anthropic; if it is accepted the provider is switched on.
func (c *Client) VerifyAnthropicFederation(name string) (*FederationVerification, error) {
	var data struct {
		Verify FederationVerification `json:"verifyMcpUpstreamFederation"`
	}
	q := `mutation($name: String!) { verifyMcpUpstreamFederation(name: $name) { verified reason } }`
	if err := c.graphql(q, map[string]any{"name": name}, &data); err != nil {
		return nil, fmt.Errorf("verify federation: %w", err)
	}
	return &data.Verify, nil
}

// SetMcpUpstreamEnabled switches an upstream on or off.
func (c *Client) SetMcpUpstreamEnabled(name string, enabled bool) error {
	q := `mutation($name: String!, $enabled: Boolean!) { setMcpUpstreamEnabled(name: $name, enabled: $enabled) { id } }`
	if err := c.graphql(q, map[string]any{"name": name, "enabled": enabled}, nil); err != nil {
		return fmt.Errorf("set provider enabled: %w", err)
	}
	return nil
}

// RemoveMcpUpstream deletes an upstream. An upstream that is already gone is not an error.
func (c *Client) RemoveMcpUpstream(name string) error {
	q := `mutation($name: String!) { removeMcpUpstream(name: $name) }`
	if err := c.graphql(q, map[string]any{"name": name}, nil); err != nil {
		if IsUpstreamNotFound(err) {
			return nil
		}
		return fmt.Errorf("remove provider: %w", err)
	}
	return nil
}

// IsUpstreamNotFound reports the gateway's upstream_not_found refusal.
func IsUpstreamNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "upstream_not_found")
}
