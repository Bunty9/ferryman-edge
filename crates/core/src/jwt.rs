//! JWT verification with an in-memory cache.
//!
//! `jsonwebtoken` 9 does the heavy lifting (RS256, exp/nbf checks). `moka`
//! caches successful verifications by token string — same token within the
//! TTL window skips the asymmetric-crypto round trip. Default capacity is
//! 10k entries; default TTL is 5 minutes. Both are intentional and
//! defensible: tokens larger than a few KB are unusual, and 5 minutes is
//! the standard "stale auth tolerance" window for in-line proxies.

use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use moka::future::Cache;

/// Minimal claims surface — extend as needed. `sub` is the tenant key used
/// by the rate limiter.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub scope: String,
}

pub struct JwtVerifier {
    key: DecodingKey,
    validation: Validation,
    cache: Cache<String, Claims>,
}

impl JwtVerifier {
    /// Construct from a PEM-encoded RSA public key. Set up RS256 validation
    /// and a 10k-entry LRU cache with a 5-minute TTL.
    pub fn new(jwks_pem: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            key: DecodingKey::from_rsa_pem(jwks_pem)?,
            validation: Validation::new(Algorithm::RS256),
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(std::time::Duration::from_secs(300))
                .build(),
        })
    }

    /// Returns the validated claims if the token verifies. Cache hit on
    /// repeated invocations within the TTL window.
    pub async fn verify(&self, token: &str) -> Option<Claims> {
        if let Some(claims) = self.cache.get(token).await {
            return Some(claims);
        }
        let TokenData { claims, .. } =
            decode::<Claims>(token, &self.key, &self.validation).ok()?;
        self.cache.insert(token.to_string(), claims.clone()).await;
        Some(claims)
    }
}
