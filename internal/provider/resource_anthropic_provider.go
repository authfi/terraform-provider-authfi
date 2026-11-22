package provider

import (
	"context"
	"fmt"

	"github.com/authfi/terraform-provider-authfi/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &AnthropicProviderResource{}
	_ resource.ResourceWithImportState = &AnthropicProviderResource{}
)

// Subject scopes of a keyless provider.
const (
	subjectScopeConnection = "connection"
	subjectScopeAgent      = "agent"
)

// AnthropicProviderResource registers a keyless Anthropic model provider (auth kind federated) in the AI gateway and
// exposes what AuthFI asserts, which the customer's Anthropic organization must trust. The Anthropic ids are bound by
// authfi_anthropic_provider_federation, a separate resource because the rule that holds them can only be created once
// this one has produced the issuer, subject and audience.
type AnthropicProviderResource struct {
	client *client.Client
}

type AnthropicProviderResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	SubjectScope         types.String `tfsdk:"subject_scope"`
	IssuerURL            types.String `tfsdk:"issuer_url"`
	DiscoveryURL         types.String `tfsdk:"discovery_url"`
	JWKSURL              types.String `tfsdk:"jwks_url"`
	Subject              types.String `tfsdk:"subject"`
	SubjectPrefix        types.String `tfsdk:"subject_prefix"`
	Audience             types.String `tfsdk:"audience"`
	OAuthScope           types.String `tfsdk:"oauth_scope"`
	TokenLifetimeSeconds types.Int64  `tfsdk:"token_lifetime_seconds"`
	Bound                types.Bool   `tfsdk:"bound"`
	Enabled              types.Bool   `tfsdk:"enabled"`
}

func NewAnthropicProviderResource() resource.Resource {
	return &AnthropicProviderResource{}
}

func (r *AnthropicProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_anthropic_provider"
}

// oneOfString is the validator for an attribute with a closed set of values.
type oneOfString struct{ values []string }

func (v oneOfString) Description(_ context.Context) string {
	return fmt.Sprintf("value must be one of %v", v.values)
}

func (v oneOfString) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v oneOfString) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	for _, ok := range v.values {
		if req.ConfigValue.ValueString() == ok {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Invalid value",
		fmt.Sprintf("%q is not valid: %s.", req.ConfigValue.ValueString(), v.Description(context.Background())))
}

func computedString(description string) schema.StringAttribute {
	return schema.StringAttribute{
		Computed:    true,
		Description: description,
		PlanModifiers: []planmodifier.String{
			stringplanmodifier.UseStateForUnknown(),
		},
	}
}

func (r *AnthropicProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Registers a keyless Anthropic model provider in the AI gateway. AuthFI is the OIDC issuer the customer's " +
			"Anthropic organization trusts (Workload Identity Federation), so no Anthropic API key is stored. The provider is " +
			"registered off; authfi_anthropic_provider_federation binds the Anthropic ids and switches it on. Every attribute " +
			"is fixed at registration: changing the name or subject scope replaces the provider.",
		Attributes: map[string]schema.Attribute{
			"id": computedString("Provider ID: the connection ID and the last part of the subject."),
			"name": schema.StringAttribute{
				Required: true,
				Description: "Provider name, the catalogue namespace (a letter, then letters, digits, '-' and single '_', at most 32 " +
					"characters). Changing it replaces the provider.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"subject_scope": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(subjectScopeConnection),
				Description: "Whose identity Anthropic sees. 'connection' (default): one identity for the provider. 'agent': the " +
					"identity names the calling agent, so each agent can have its own rule and service account. It decides the " +
					"subject, so changing it replaces the provider.",
				Validators:    []validator.String{oneOfString{values: []string{subjectScopeConnection, subjectScopeAgent}}},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"issuer_url":     computedString("Issuer URL to register as a Custom OIDC issuer in Anthropic. Fixed once registered."),
			"discovery_url":  computedString("OIDC discovery URL of the issuer."),
			"jwks_url":       computedString("JWKS URL of the issuer."),
			"subject":        computedString("The subject this provider presents to Anthropic."),
			"subject_prefix": computedString("The narrowest rule match that admits the subject, and the agent subjects beneath it."),
			"audience":       computedString("The audience the Anthropic rule must match."),
			"oauth_scope":    computedString("The OAuth scope to create the Anthropic rule with."),
			"token_lifetime_seconds": schema.Int64Attribute{
				Computed:    true,
				Description: "The token lifetime to create the Anthropic rule with.",
			},
			"bound": schema.BoolAttribute{
				Computed:    true,
				Description: "True when all four Anthropic ids are recorded (see authfi_anthropic_provider_federation).",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True once the provider is on: a verify exchange succeeded, or it was switched on.",
			},
		},
	}
}

func (r *AnthropicProviderResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

// apply copies what the gateway returned into the model.
func (m *AnthropicProviderResourceModel) apply(u *client.McpUpstream) {
	m.ID = types.StringValue(u.ID)
	m.Name = types.StringValue(u.Name)
	m.Enabled = types.BoolValue(u.Enabled)
	f := u.Federation
	if f == nil {
		return
	}
	if f.ProviderID != "" {
		m.ID = types.StringValue(f.ProviderID)
	}
	m.SubjectScope = types.StringValue(f.SubjectScope)
	m.IssuerURL = types.StringValue(f.IssuerURL)
	m.DiscoveryURL = types.StringValue(f.DiscoveryURL)
	m.JWKSURL = types.StringValue(f.JWKSURL)
	m.Subject = types.StringValue(f.Subject)
	m.SubjectPrefix = types.StringValue(f.SubjectPrefix)
	m.Audience = types.StringValue(f.Audience)
	m.OAuthScope = types.StringValue(f.OAuthScope)
	m.TokenLifetimeSeconds = types.Int64Value(f.TokenLifetimeSeconds)
	m.Bound = types.BoolValue(f.Bound)
	m.Enabled = types.BoolValue(f.Enabled)
}

// keylessProviderProblem explains why an upstream is not a keyless Anthropic provider, or returns "".
func keylessProviderProblem(u *client.McpUpstream) string {
	switch {
	case u.Transport != client.TransportAnthropic || u.AuthKind != client.AuthKindFederated:
		return fmt.Sprintf("upstream %q exists but is not a keyless Anthropic provider (transport %q, auth kind %q)", u.Name, u.Transport, u.AuthKind)
	case u.Federation == nil:
		return fmt.Sprintf("the gateway returned no federation state for keyless provider %q", u.Name)
	}
	return ""
}

func (r *AnthropicProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AnthropicProviderResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	u, err := r.client.RegisterAnthropicProvider(plan.Name.ValueString(), plan.SubjectScope.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Register Anthropic Provider Failed", err.Error())
		return
	}
	if problem := keylessProviderProblem(u); problem != "" {
		resp.Diagnostics.AddError("Register Anthropic Provider Failed", problem)
		return
	}
	plan.apply(u)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AnthropicProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AnthropicProviderResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	u, err := r.client.GetMcpUpstream(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read Anthropic Provider Failed", err.Error())
		return
	}
	if u == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	if problem := keylessProviderProblem(u); problem != "" {
		resp.Diagnostics.AddError("Read Anthropic Provider Failed", problem)
		return
	}
	state.apply(u)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is unreachable: every configurable attribute forces replacement, and the rest are computed.
func (r *AnthropicProviderResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update Not Supported", "A keyless Anthropic provider cannot be updated in place. Replace it instead.")
}

func (r *AnthropicProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AnthropicProviderResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RemoveMcpUpstream(state.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Remove Anthropic Provider Failed", err.Error())
	}
}

// ImportState imports by provider name.
func (r *AnthropicProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
