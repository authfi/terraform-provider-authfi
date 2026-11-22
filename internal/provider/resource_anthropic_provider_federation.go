package provider

import (
	"context"
	"fmt"

	"github.com/authfi/terraform-provider-authfi/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &AnthropicProviderFederationResource{}
	_ resource.ResourceWithImportState = &AnthropicProviderFederationResource{}
)

// AnthropicProviderFederationResource binds the four Anthropic ids to a keyless provider and proves them with one real
// token exchange, which switches the provider on. It is separate from authfi_anthropic_provider so there is no cycle with
// the resources that create the Anthropic rule from that provider's issuer, subject and audience.
type AnthropicProviderFederationResource struct {
	client *client.Client
}

type AnthropicProviderFederationResourceModel struct {
	ID               types.String `tfsdk:"id"`
	ProviderName     types.String `tfsdk:"provider_name"`
	OrganizationID   types.String `tfsdk:"organization_id"`
	FederationRuleID types.String `tfsdk:"federation_rule_id"`
	ServiceAccountID types.String `tfsdk:"service_account_id"`
	WorkspaceID      types.String `tfsdk:"workspace_id"`
	Enabled          types.Bool   `tfsdk:"enabled"`
}

func NewAnthropicProviderFederationResource() resource.Resource {
	return &AnthropicProviderFederationResource{}
}

func (r *AnthropicProviderFederationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_anthropic_provider_federation"
}

func (r *AnthropicProviderFederationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Binds the Anthropic organization, federation rule, service account and workspace ids to a keyless Anthropic " +
			"provider and verifies them with one real token exchange. The provider is switched on only when Anthropic accepts the " +
			"exchange; a refusal fails the apply with the gateway's reason. None of the ids is a secret. Destroying this resource " +
			"switches the provider off (the gateway cannot clear bound ids).",
		Attributes: map[string]schema.Attribute{
			"id": computedString("The provider ID."),
			"provider_name": schema.StringAttribute{
				Required:      true,
				Description:   "Name of the authfi_anthropic_provider. Changing it replaces this binding.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"organization_id": schema.StringAttribute{
				Required:    true,
				Description: "The customer's Anthropic organization ID.",
			},
			"federation_rule_id": schema.StringAttribute{
				Required:    true,
				Description: "The Anthropic federation rule ID (fdrl_...) that trusts the provider's issuer and subject.",
			},
			"service_account_id": schema.StringAttribute{
				Required:    true,
				Description: "The Anthropic service account ID (svac_...) the rule maps to.",
			},
			"workspace_id": schema.StringAttribute{
				Required:    true,
				Description: "The Anthropic workspace ID (wrkspc_...) model calls are made in.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the provider is on. An admin can switch it off outside Terraform; the next refresh shows it.",
			},
		},
	}
}

func (r *AnthropicProviderFederationResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client.Client)
}

// bindAndVerify stores the ids and proves them. The bind is idempotent, so a failed verify is retried by the next apply.
func (r *AnthropicProviderFederationResource) bindAndVerify(m *AnthropicProviderFederationResourceModel) (*client.McpFederation, error) {
	name := m.ProviderName.ValueString()
	bound, err := r.client.BindAnthropicFederation(name, client.BindFederationInput{
		OrganizationID:   m.OrganizationID.ValueString(),
		FederationRuleID: m.FederationRuleID.ValueString(),
		ServiceAccountID: m.ServiceAccountID.ValueString(),
		WorkspaceID:      m.WorkspaceID.ValueString(),
	})
	if err != nil {
		return nil, err
	}
	v, err := r.client.VerifyAnthropicFederation(name)
	if err != nil {
		return nil, err
	}
	if !v.Verified {
		reason := "no reason given"
		if v.Reason != nil && *v.Reason != "" {
			reason = *v.Reason
		}
		return nil, fmt.Errorf("Anthropic did not accept the token exchange for provider %q: %s. The ids are bound and the provider stays off; "+
			"check the rule's issuer, subject and audience against authfi_anthropic_provider, then apply again", name, reason)
	}
	bound.Enabled = true
	return bound, nil
}

func (m *AnthropicProviderFederationResourceModel) apply(f *client.McpFederation) {
	m.ID = types.StringValue(f.ProviderID)
	m.Enabled = types.BoolValue(f.Enabled)
	if f.OrganizationID != nil {
		m.OrganizationID = types.StringValue(*f.OrganizationID)
	}
	if f.FederationRuleID != nil {
		m.FederationRuleID = types.StringValue(*f.FederationRuleID)
	}
	if f.ServiceAccountID != nil {
		m.ServiceAccountID = types.StringValue(*f.ServiceAccountID)
	}
	if f.WorkspaceID != nil {
		m.WorkspaceID = types.StringValue(*f.WorkspaceID)
	}
}

func (r *AnthropicProviderFederationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AnthropicProviderFederationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	f, err := r.bindAndVerify(&plan)
	if err != nil {
		resp.Diagnostics.AddError("Bind Anthropic Federation Failed", err.Error())
		return
	}
	plan.apply(f)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AnthropicProviderFederationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AnthropicProviderFederationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	u, err := r.client.GetMcpUpstream(state.ProviderName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read Anthropic Federation Failed", err.Error())
		return
	}
	if u == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	if problem := keylessProviderProblem(u); problem != "" {
		resp.Diagnostics.AddError("Read Anthropic Federation Failed", problem)
		return
	}
	if !u.Federation.Bound {
		resp.State.RemoveResource(ctx)
		return
	}
	state.apply(u.Federation)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *AnthropicProviderFederationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan AnthropicProviderFederationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	f, err := r.bindAndVerify(&plan)
	if err != nil {
		resp.Diagnostics.AddError("Update Anthropic Federation Failed", err.Error())
		return
	}
	plan.apply(f)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete switches the provider off. The gateway has no call that clears bound ids, so they remain until the provider is
// removed; a provider that is already gone is not an error.
func (r *AnthropicProviderFederationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AnthropicProviderFederationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.SetMcpUpstreamEnabled(state.ProviderName.ValueString(), false); err != nil && !client.IsUpstreamNotFound(err) {
		resp.Diagnostics.AddError("Switch Anthropic Provider Off Failed", err.Error())
	}
}

// ImportState imports by provider name.
func (r *AnthropicProviderFederationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("provider_name"), req.ID)...)
}
