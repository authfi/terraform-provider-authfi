package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gql is a fake BFF: it records each request and answers with the next canned body.
type gql struct {
	t      *testing.T
	bodies []string
	seen   []graphQLRequest
	auth   []string
	status int
}

func (g *gql) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req graphQLRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		g.t.Errorf("request is not graphql json: %v", err)
	}
	g.seen = append(g.seen, req)
	g.auth = append(g.auth, r.Header.Get("Authorization"))
	if g.status != 0 {
		w.WriteHeader(g.status)
	}
	_, _ = w.Write([]byte(g.bodies[len(g.seen)-1]))
}

func newFake(t *testing.T, bodies ...string) (*Client, *gql) {
	g := &gql{t: t, bodies: bodies}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	c := New("sk_test", "acme")
	c.GraphQLURL = srv.URL + "/graphql"
	return c, g
}

const trust = `"providerId":"p1","issuerUrl":"https://acme.authfi.io/oidc","discoveryUrl":"d","jwksUrl":"j","subject":"s","subjectPrefix":"sp","audience":"https://api.anthropic.com","oauthScope":"workspace:inference","tokenLifetimeSeconds":600,"subjectScope":"connection","bound":false,"enabled":false,"organizationId":null,"federationRuleId":null,"serviceAccountId":null,"workspaceId":null`

func TestRegisterSendsAFederatedAnthropicProviderWithNoKeyAndNoURL(t *testing.T) {
	c, g := newFake(t, `{"data":{"registerMcpUpstream":{"id":"p1","name":"claude","transport":"anthropic","authKind":"federated","enabled":false,"federation":{`+trust+`}}}}`)
	u, err := c.RegisterAnthropicProvider("claude", "agent")
	if err != nil {
		t.Fatal(err)
	}
	in := g.seen[0].Variables["input"].(map[string]any)
	if in["transport"] != "anthropic" || in["authKind"] != "federated" || in["subjectScope"] != "agent" || in["name"] != "claude" {
		t.Fatalf("input = %v", in)
	}
	if in["url"] != "" {
		t.Fatalf("a keyless provider takes no url, sent %q", in["url"])
	}
	if _, has := in["credential"]; has {
		t.Fatal("a keyless provider must send no credential")
	}
	if g.auth[0] != "Bearer sk_test" {
		t.Fatalf("auth = %q", g.auth[0])
	}
	if u.Federation == nil || u.Federation.Audience != "https://api.anthropic.com" || u.Federation.OrganizationID != nil {
		t.Fatalf("federation = %+v", u.Federation)
	}
}

func TestRegisterOmitsSubjectScopeWhenUnset(t *testing.T) {
	c, g := newFake(t, `{"data":{"registerMcpUpstream":{"id":"p1","name":"claude","transport":"anthropic","authKind":"federated","enabled":false,"federation":null}}}`)
	if _, err := c.RegisterAnthropicProvider("claude", ""); err != nil {
		t.Fatal(err)
	}
	if _, has := g.seen[0].Variables["input"].(map[string]any)["subjectScope"]; has {
		t.Fatal("an unset scope must be left to the gateway's default")
	}
}

func TestGraphQLErrorsAreFailuresNotValues(t *testing.T) {
	c, _ := newFake(t, `{"data":null,"errors":[{"message":"forbidden"},{"message":"confirm it's you"}]}`)
	_, err := c.RegisterAnthropicProvider("claude", "")
	if err == nil || !strings.Contains(err.Error(), "forbidden; confirm it's you") {
		t.Fatalf("err = %v", err)
	}
}

func TestNon200IsAFailure(t *testing.T) {
	c, g := newFake(t, `unauthorized`)
	g.status = 401
	if _, err := c.GetMcpUpstream("claude"); err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("err = %v", err)
	}
}

func TestGetFindsByNameAndReturnsNilWhenAbsent(t *testing.T) {
	body := `{"data":{"mcpUpstreams":[{"id":"x","name":"other","transport":"http","authKind":"bearer","enabled":true,"federation":null},{"id":"p1","name":"claude","transport":"anthropic","authKind":"federated","enabled":true,"federation":{` + trust + `}}]}}`
	c, _ := newFake(t, body, body)
	u, err := c.GetMcpUpstream("claude")
	if err != nil || u == nil || u.ID != "p1" {
		t.Fatalf("u=%+v err=%v", u, err)
	}
	if u, err = c.GetMcpUpstream("missing"); err != nil || u != nil {
		t.Fatalf("u=%+v err=%v", u, err)
	}
}

func TestBindSendsTheFourIDsAndNoScope(t *testing.T) {
	c, g := newFake(t, `{"data":{"bindMcpUpstreamFederation":{`+strings.Replace(trust, `"bound":false`, `"bound":true`, 1)+`}}}`)
	f, err := c.BindAnthropicFederation("claude", BindFederationInput{"org", "fdrl_1", "svac_1", "wrkspc_1"})
	if err != nil {
		t.Fatal(err)
	}
	if g.seen[0].Variables["name"] != "claude" {
		t.Fatalf("vars = %v", g.seen[0].Variables)
	}
	in := g.seen[0].Variables["input"].(map[string]any)
	want := map[string]any{"organizationId": "org", "federationRuleId": "fdrl_1", "serviceAccountId": "svac_1", "workspaceId": "wrkspc_1"}
	if len(in) != 4 {
		t.Fatalf("input = %v", in)
	}
	for k, v := range want {
		if in[k] != v {
			t.Fatalf("%s = %v", k, in[k])
		}
	}
	if !f.Bound {
		t.Fatal("bound not decoded")
	}
}

func TestVerifyDecodesTheReason(t *testing.T) {
	c, _ := newFake(t, `{"data":{"verifyMcpUpstreamFederation":{"verified":false,"reason":"exchange_denied"}}}`)
	v, err := c.VerifyAnthropicFederation("claude")
	if err != nil || v.Verified || v.Reason == nil || *v.Reason != "exchange_denied" {
		t.Fatalf("v=%+v err=%v", v, err)
	}
}

func TestRemoveToleratesAnUpstreamThatIsGone(t *testing.T) {
	c, _ := newFake(t, `{"data":null,"errors":[{"message":"upstream_not_found"}]}`, `{"data":null,"errors":[{"message":"kms down"}]}`)
	if err := c.RemoveMcpUpstream("claude"); err != nil {
		t.Fatalf("gone upstream: %v", err)
	}
	if err := c.RemoveMcpUpstream("claude"); err == nil {
		t.Fatal("another failure must not be swallowed")
	}
}

func TestEndpointDefaultsToTheTenantsOrigin(t *testing.T) {
	if got := New("k", "acme").graphqlEndpoint(); got != "https://acme.authfi.io/graphql" {
		t.Fatalf("endpoint = %q", got)
	}
}
