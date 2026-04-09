use crate::config::OidcConfig;

/// OIDC client for authenticating users via an external Identity Provider (SR-001).
///
/// Flow:
/// 1. User initiates login -> redirect to IdP authorization endpoint
/// 2. IdP redirects back with auth code
/// 3. Backend exchanges code for ID token + access token
/// 4. Backend maps OIDC claims to internal Role and creates a short-lived JWT
pub struct OidcClient {
    _config: OidcConfig,
}

impl OidcClient {
    pub fn new(config: OidcConfig) -> Self {
        Self { _config: config }
    }

    // TODO: Implement authorization URL generation
    // TODO: Implement auth code exchange
    // TODO: Implement userinfo fetching and role mapping
}
