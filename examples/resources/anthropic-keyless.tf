# Keyless Anthropic model provider: AuthFI is the OIDC issuer the Anthropic organization trusts
# (Workload Identity Federation). No Anthropic API key is stored in AuthFI or in this configuration.
#
# The provider talks to the project's GraphQL endpoint (default https://<tenant>.authfi.io/graphql;
# set graphql_url or AUTHFI_GRAPHQL_URL for a non-production host).

# Step 1: register the provider. It is stored off, and AuthFI reports what the customer's Anthropic
# organization must trust.
resource "authfi_anthropic_provider" "claude" {
  name          = "claude"
  subject_scope = "connection" # or "agent": one Anthropic identity per calling agent
}

# Step 2: create the issuer and the rule in Anthropic from those values, with whatever manages the
# Anthropic organization (the Anthropic console or its Admin API). Paste:
#   issuer URL      authfi_anthropic_provider.claude.issuer_url
#   subject         authfi_anthropic_provider.claude.subject   (or subject_prefix for a prefix match)
#   audience        authfi_anthropic_provider.claude.audience
#   OAuth scope     authfi_anthropic_provider.claude.oauth_scope
#   token lifetime  authfi_anthropic_provider.claude.token_lifetime_seconds

# Step 3: bind the ids Anthropic shows back and verify them. The apply makes one real token exchange;
# the provider is switched on only if Anthropic accepts it, and a refusal fails the apply with the
# gateway's reason (for example exchange_denied).
resource "authfi_anthropic_provider_federation" "claude" {
  provider_name      = authfi_anthropic_provider.claude.name
  organization_id    = var.anthropic_org_id
  federation_rule_id = var.anthropic_federation_rule_id
  service_account_id = var.anthropic_service_account_id
  workspace_id       = var.anthropic_workspace_id
}

variable "anthropic_org_id" { type = string }
variable "anthropic_federation_rule_id" { type = string }
variable "anthropic_service_account_id" { type = string }
variable "anthropic_workspace_id" { type = string }

output "anthropic_issuer_url" {
  value = authfi_anthropic_provider.claude.issuer_url
}

output "anthropic_subject" {
  value = authfi_anthropic_provider.claude.subject
}

output "anthropic_audience" {
  value = authfi_anthropic_provider.claude.audience
}

output "anthropic_provider_on" {
  value = authfi_anthropic_provider_federation.claude.enabled
}
