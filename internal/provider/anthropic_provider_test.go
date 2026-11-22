package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authfi/terraform-provider-authfi/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const fedTrust = `"providerId":"p1","issuerUrl":"https://acme.authfi.io/oidc","discoveryUrl":"d","jwksUrl":"j","subject":"authfi:v1:project:t:model:p1","subjectPrefix":"authfi:v1:project:t:model:p1","audience":"https://api.anthropic.com","oauthScope":"workspace:inference","tokenLifetimeSeconds":600,"subjectScope":"connection"`

// fakeBFF answers each operation by the field name it calls and records the order.
type fakeBFF struct {
	ops     []string
	answers map[string]string
}

func (f *fakeBFF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req struct{ Query string }
	_ = json.Unmarshal(raw, &req)
	for op, ans := range f.answers {
		if strings.Contains(req.Query, op) {
			f.ops = append(f.ops, op)
			_, _ = w.Write([]byte(ans))
			return
		}
	}
	http.Error(w, "unexpected "+req.Query, 500)
}

func fakeClient(t *testing.T, answers map[string]string) (*client.Client, *fakeBFF) {
	f := &fakeBFF{answers: answers}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := client.New("sk", "acme")
	c.GraphQLURL = srv.URL
	return c, f
}

func schemaOf(t *testing.T, r resource.Resource) schema.Schema {
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if d := resp.Schema.ValidateImplementation(context.Background()); d.HasError() {
		t.Fatalf("schema: %v", d)
	}
	return resp.Schema
}

func planOf(s schema.Schema, vals map[string]tftypes.Value) tfsdk.Plan {
	typ := s.Type().TerraformType(context.Background()).(tftypes.Object)
	all := map[string]tftypes.Value{}
	for name, at := range typ.AttributeTypes {
		if v, ok := vals[name]; ok {
			all[name] = v
		} else {
			all[name] = tftypes.NewValue(at, nil)
		}
	}
	return tfsdk.Plan{Schema: s, Raw: tftypes.NewValue(typ, all)}
}

func emptyState(s schema.Schema) tfsdk.State {
	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(context.Background()), nil)}
}

func str(v string) tftypes.Value { return tftypes.NewValue(tftypes.String, v) }

func TestAnthropicResourcesAreRegistered(t *testing.T) {
	p := New("test")().(*AuthFIProvider)
	names := map[string]bool{}
	for _, f := range p.Resources(context.Background()) {
		var resp resource.MetadataResponse
		f().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "authfi"}, &resp)
		names[resp.TypeName] = true
	}
	for _, want := range []string{"authfi_anthropic_provider", "authfi_anthropic_provider_federation"} {
		if !names[want] {
			t.Errorf("%s is not registered", want)
		}
	}
}

func TestProviderForcesReplacementAndExposesReadOnlyTrust(t *testing.T) {
	s := schemaOf(t, NewAnthropicProviderResource())
	for _, name := range []string{"name", "subject_scope"} {
		a := s.Attributes[name].(schema.StringAttribute)
		forced := false
		for _, m := range a.PlanModifiers {
			if strings.Contains(m.Description(context.Background()), "destroy and recreate") {
				forced = true
			}
		}
		if !forced {
			t.Errorf("%s must force replacement: the gateway has no call that changes it", name)
		}
	}
	for _, name := range []string{"id", "issuer_url", "discovery_url", "jwks_url", "subject", "subject_prefix", "audience", "oauth_scope", "token_lifetime_seconds", "bound", "enabled"} {
		a := s.Attributes[name]
		if !a.IsComputed() || a.IsOptional() || a.IsRequired() {
			t.Errorf("%s must be read-only", name)
		}
	}
}

func TestFederationIDsUpdateInPlaceButTheProviderNameDoesNot(t *testing.T) {
	s := schemaOf(t, NewAnthropicProviderFederationResource())
	if len(s.Attributes["provider_name"].(schema.StringAttribute).PlanModifiers) == 0 {
		t.Error("provider_name must force replacement")
	}
	for _, name := range []string{"organization_id", "federation_rule_id", "service_account_id", "workspace_id"} {
		a := s.Attributes[name].(schema.StringAttribute)
		if !a.IsRequired() || len(a.PlanModifiers) != 0 {
			t.Errorf("%s must be required and updatable in place (the gateway rebinds the ids)", name)
		}
	}
}

func TestSubjectScopeValidatorRefusesAnythingButConnectionOrAgent(t *testing.T) {
	v := oneOfString{values: []string{subjectScopeConnection, subjectScopeAgent}}
	for val, bad := range map[string]bool{"connection": false, "agent": false, "user": true, "": true} {
		var resp validator.StringResponse
		v.ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue(val)}, &resp)
		if resp.Diagnostics.HasError() != bad {
			t.Errorf("%q: error=%v want %v", val, resp.Diagnostics.HasError(), bad)
		}
	}
	var resp validator.StringResponse
	v.ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringUnknown()}, &resp)
	if resp.Diagnostics.HasError() {
		t.Error("an unknown value is validated at apply, not at plan")
	}
}

func TestProviderCreateRegistersAndShowsWhatAuthFIAsserts(t *testing.T) {
	c, f := fakeClient(t, map[string]string{
		"registerMcpUpstream": `{"data":{"registerMcpUpstream":{"id":"p1","name":"claude","transport":"anthropic","authKind":"federated","enabled":false,"federation":{` + fedTrust + `,"bound":false,"enabled":false}}}}`,
	})
	r := &AnthropicProviderResource{client: c}
	s := schemaOf(t, r)
	resp := resource.CreateResponse{State: emptyState(s)}
	r.Create(context.Background(), resource.CreateRequest{Plan: planOf(s, map[string]tftypes.Value{
		"name": str("claude"), "subject_scope": str("connection"),
	})}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var got AnthropicProviderResourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &got)...)
	if got.ID.ValueString() != "p1" || got.IssuerURL.ValueString() != "https://acme.authfi.io/oidc" ||
		got.Audience.ValueString() != "https://api.anthropic.com" || got.Subject.ValueString() == "" ||
		got.Bound.ValueBool() || got.Enabled.ValueBool() || got.TokenLifetimeSeconds.ValueInt64() != 600 {
		t.Fatalf("state = %+v", got)
	}
	if len(f.ops) != 1 {
		t.Fatalf("ops = %v", f.ops)
	}
}

func TestProviderReadRemovesAProviderThatIsGoneAndRefusesAForeignOne(t *testing.T) {
	c, _ := fakeClient(t, map[string]string{"mcpUpstreams": `{"data":{"mcpUpstreams":[]}}`})
	r := &AnthropicProviderResource{client: c}
	s := schemaOf(t, r)
	st := tfsdk.State{Schema: s, Raw: planOf(s, map[string]tftypes.Value{"name": str("claude")}).Raw}
	resp := resource.ReadResponse{State: st}
	r.Read(context.Background(), resource.ReadRequest{State: st}, &resp)
	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Fatalf("a removed provider must leave state: %v", resp.Diagnostics)
	}

	c, _ = fakeClient(t, map[string]string{"mcpUpstreams": `{"data":{"mcpUpstreams":[{"id":"x","name":"claude","transport":"openai","authKind":"bearer","enabled":true,"federation":null}]}}`})
	r = &AnthropicProviderResource{client: c}
	resp = resource.ReadResponse{State: st}
	r.Read(context.Background(), resource.ReadRequest{State: st}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("an upstream of another kind under this name must be an error, never adopted")
	}
}

func fedPlan(s schema.Schema) tfsdk.Plan {
	return planOf(s, map[string]tftypes.Value{
		"provider_name": str("claude"), "organization_id": str("org"), "federation_rule_id": str("fdrl_1"),
		"service_account_id": str("svac_1"), "workspace_id": str("wrkspc_1"),
	})
}

const boundTrust = `{` + fedTrust + `,"bound":true,"enabled":false,"organizationId":"org","federationRuleId":"fdrl_1","serviceAccountId":"svac_1","workspaceId":"wrkspc_1"}`

func TestFederationCreateBindsThenVerifiesAndReportsOn(t *testing.T) {
	c, f := fakeClient(t, map[string]string{
		"bindMcpUpstreamFederation":   `{"data":{"bindMcpUpstreamFederation":` + boundTrust + `}}`,
		"verifyMcpUpstreamFederation": `{"data":{"verifyMcpUpstreamFederation":{"verified":true,"reason":null}}}`,
	})
	r := &AnthropicProviderFederationResource{client: c}
	s := schemaOf(t, r)
	resp := resource.CreateResponse{State: emptyState(s)}
	r.Create(context.Background(), resource.CreateRequest{Plan: fedPlan(s)}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if strings.Join(f.ops, ",") != "bindMcpUpstreamFederation,verifyMcpUpstreamFederation" {
		t.Fatalf("order = %v", f.ops)
	}
	var got AnthropicProviderFederationResourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &got)...)
	if !got.Enabled.ValueBool() || got.ID.ValueString() != "p1" || got.WorkspaceID.ValueString() != "wrkspc_1" {
		t.Fatalf("state = %+v", got)
	}
}

func TestFederationCreateFailsWithTheReasonAndSavesNothingWhenAnthropicRefuses(t *testing.T) {
	c, _ := fakeClient(t, map[string]string{
		"bindMcpUpstreamFederation":   `{"data":{"bindMcpUpstreamFederation":` + boundTrust + `}}`,
		"verifyMcpUpstreamFederation": `{"data":{"verifyMcpUpstreamFederation":{"verified":false,"reason":"exchange_denied"}}}`,
	})
	r := &AnthropicProviderFederationResource{client: c}
	s := schemaOf(t, r)
	resp := resource.CreateResponse{State: emptyState(s)}
	r.Create(context.Background(), resource.CreateRequest{Plan: fedPlan(s)}, &resp)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "exchange_denied") {
		t.Fatalf("diagnostics = %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatal("an unverified binding must not be recorded as success")
	}
}

func TestFederationReadDropsABindingThatIsNoLongerBound(t *testing.T) {
	c, _ := fakeClient(t, map[string]string{"mcpUpstreams": `{"data":{"mcpUpstreams":[{"id":"p1","name":"claude","transport":"anthropic","authKind":"federated","enabled":false,"federation":{` + fedTrust + `,"bound":false,"enabled":false}}]}}`})
	r := &AnthropicProviderFederationResource{client: c}
	s := schemaOf(t, r)
	st := tfsdk.State{Schema: s, Raw: fedPlan(s).Raw}
	resp := resource.ReadResponse{State: st}
	r.Read(context.Background(), resource.ReadRequest{State: st}, &resp)
	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Fatalf("an unbound upstream must leave state so the next plan rebinds: %v", resp.Diagnostics)
	}
}

func TestFederationReadShowsIDsChangedOutsideTerraform(t *testing.T) {
	drifted := strings.Replace(strings.Replace(boundTrust, `"fdrl_1"`, `"fdrl_2"`, 1), `"enabled":false`, `"enabled":true`, 1)
	c, _ := fakeClient(t, map[string]string{"mcpUpstreams": `{"data":{"mcpUpstreams":[{"id":"p1","name":"claude","transport":"anthropic","authKind":"federated","enabled":true,"federation":` + drifted + `}]}}`})
	r := &AnthropicProviderFederationResource{client: c}
	s := schemaOf(t, r)
	st := tfsdk.State{Schema: s, Raw: fedPlan(s).Raw}
	resp := resource.ReadResponse{State: st}
	r.Read(context.Background(), resource.ReadRequest{State: st}, &resp)
	var got AnthropicProviderFederationResourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &got)...)
	if got.FederationRuleID.ValueString() != "fdrl_2" || !got.Enabled.ValueBool() {
		t.Fatalf("drift not shown: %+v", got)
	}
}

func TestFederationDeleteSwitchesTheProviderOffAndToleratesItBeingGone(t *testing.T) {
	for name, ans := range map[string]string{
		"off":  `{"data":{"setMcpUpstreamEnabled":{"id":"p1"}}}`,
		"gone": `{"data":null,"errors":[{"message":"upstream_not_found"}]}`,
	} {
		c, f := fakeClient(t, map[string]string{"setMcpUpstreamEnabled": ans})
		r := &AnthropicProviderFederationResource{client: c}
		s := schemaOf(t, r)
		resp := resource.DeleteResponse{}
		r.Delete(context.Background(), resource.DeleteRequest{State: tfsdk.State{Schema: s, Raw: fedPlan(s).Raw}}, &resp)
		if resp.Diagnostics.HasError() || len(f.ops) != 1 {
			t.Errorf("%s: ops=%v diags=%v", name, f.ops, resp.Diagnostics)
		}
	}
}

func TestProviderDeleteRemovesTheProvider(t *testing.T) {
	c, f := fakeClient(t, map[string]string{"removeMcpUpstream": `{"data":{"removeMcpUpstream":true}}`})
	r := &AnthropicProviderResource{client: c}
	s := schemaOf(t, r)
	resp := resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: tfsdk.State{Schema: s, Raw: planOf(s, map[string]tftypes.Value{"name": str("claude")}).Raw}}, &resp)
	if resp.Diagnostics.HasError() || strings.Join(f.ops, ",") != "removeMcpUpstream" {
		t.Fatalf("ops=%v diags=%v", f.ops, resp.Diagnostics)
	}
}
