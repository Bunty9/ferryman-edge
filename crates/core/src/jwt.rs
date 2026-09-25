//! JWT verification with an in-memory cache.
//!
//! `jsonwebtoken` 9 does the heavy lifting (RS256, exp/nbf checks). `moka`
//! caches successful verifications by token string — same token within the
//! TTL window skips the asymmetric-crypto round trip. Default capacity is
//! 10k entries; default TTL is 5 minutes. Both are intentional and
//! defensible: tokens larger than a few KB are unusual, and 5 minutes is
//! the standard "stale auth tolerance" window for in-line proxies.
//!
//! The cache TTL (5 min) is independent of the token's own `exp`, so a
//! cache *hit* re-checks `exp` (with the same leeway `Validation` would
//! apply) before trusting the cached claims — otherwise a token that
//! expired seconds after being cached would keep verifying for up to 5
//! more minutes.

use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use moka::future::Cache;

/// Minimal claims surface — extend as needed. `sub` is the tenant key used
/// by the rate limiter.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    #[serde(default)]
    pub scope: String,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
            validation: {
                let mut v = Validation::new(Algorithm::RS256);
                // Checked once at decode; a token is only cached after it
                // passes, and a past `nbf` stays past, so hits need no recheck.
                v.validate_nbf = true;
                v
            },
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(std::time::Duration::from_secs(300))
                .build(),
        })
    }

    /// Override the leeway (seconds) applied to `exp` checks, including the
    /// cache-hit re-check. Defaults to `jsonwebtoken`'s standard 60s.
    pub fn with_leeway(mut self, secs: u64) -> Self {
        self.validation.leeway = secs;
        self
    }

    /// Require `iss` to equal `issuer`. Without it, any token signed by the
    /// issuer key is accepted, whoever it was minted for.
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.validation.set_issuer(&[issuer]);
        // `set_issuer` alone only checks `iss` when present; a token that
        // omits it would pass.
        self.validation.required_spec_claims.insert("iss".into());
        self
    }

    /// Require `aud` to contain `audience`.
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.validation.set_audience(&[audience]);
        self.validation.required_spec_claims.insert("aud".into());
        self
    }

    /// Returns the validated claims if the token verifies. Cache hit on
    /// repeated invocations within the TTL window, provided the token's own
    /// `exp` (plus leeway) hasn't passed since it was cached.
    pub async fn verify(&self, token: &str) -> Option<Claims> {
        if let Some(claims) = self.cache.get(token).await {
            if (claims.exp as u64) < now_secs().saturating_sub(self.validation.leeway) {
                return None;
            }
            return Some(claims);
        }
        let TokenData { claims, .. } = decode::<Claims>(token, &self.key, &self.validation).ok()?;
        self.cache.insert(token.to_string(), claims.clone()).await;
        Some(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    const PRIV_PEM: &[u8] = include_bytes!("../tests/fixtures/jwt-test-priv.pem");
    const OTHER_PRIV_PEM: &[u8] = include_bytes!("../tests/fixtures/jwt-test-other-priv.pem");
    const PUB_PEM: &[u8] = include_bytes!("../tests/fixtures/jwt-test-pub.pem");

    fn sign(key_pem: &[u8], claims: &Claims) -> String {
        encode(
            &Header::new(Algorithm::RS256),
            claims,
            &EncodingKey::from_rsa_pem(key_pem).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn valid_token_verifies() {
        let verifier = JwtVerifier::new(PUB_PEM).unwrap();
        let token = sign(
            PRIV_PEM,
            &Claims {
                sub: "tenant-a".into(),
                exp: now_secs() as usize + 3600,
                scope: "read".into(),
            },
        );
        let claims = verifier.verify(&token).await.expect("should verify");
        assert_eq!(claims.sub, "tenant-a");
        assert_eq!(claims.scope, "read");
    }

    fn sign_json(value: serde_json::Value) -> String {
        encode(
            &Header::new(Algorithm::RS256),
            &value,
            &EncodingKey::from_rsa_pem(PRIV_PEM).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn issuer_and_audience_enforced_when_configured() {
        let exp = now_secs() + 3600;
        let verifier = JwtVerifier::new(PUB_PEM)
            .unwrap()
            .with_issuer("https://issuer.test")
            .with_audience("ferryman-edge");
        let good = sign_json(serde_json::json!({
            "sub": "t", "exp": exp, "iss": "https://issuer.test", "aud": "ferryman-edge"
        }));
        assert!(verifier.verify(&good).await.is_some());
        for bad in [
            serde_json::json!({"sub": "t", "exp": exp, "iss": "https://evil.test", "aud": "ferryman-edge"}),
            serde_json::json!({"sub": "t", "exp": exp, "iss": "https://issuer.test", "aud": "other-svc"}),
            serde_json::json!({"sub": "t", "exp": exp}),
        ] {
            assert!(verifier.verify(&sign_json(bad)).await.is_none());
        }
    }

    #[tokio::test]
    async fn token_with_aud_rejected_when_no_audience_configured() {
        let verifier = JwtVerifier::new(PUB_PEM).unwrap();
        let token =
            sign_json(serde_json::json!({"sub": "t", "exp": now_secs() + 3600, "aud": "x"}));
        assert!(verifier.verify(&token).await.is_none());
    }

    #[tokio::test]
    async fn not_yet_valid_token_rejected() {
        let verifier = JwtVerifier::new(PUB_PEM).unwrap().with_leeway(0);
        let now = now_secs();
        let token = sign_json(serde_json::json!({"sub": "t", "exp": now + 3600, "nbf": now + 600}));
        assert!(verifier.verify(&token).await.is_none());
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let verifier = JwtVerifier::new(PUB_PEM).unwrap();
        // Signed with a key that doesn't match PUB_PEM.
        let token = sign(
            OTHER_PRIV_PEM,
            &Claims {
                sub: "tenant-a".into(),
                exp: now_secs() as usize + 3600,
                scope: "read".into(),
            },
        );
        assert!(verifier.verify(&token).await.is_none());
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let verifier = JwtVerifier::new(PUB_PEM).unwrap().with_leeway(0);
        let token = sign(
            PRIV_PEM,
            &Claims {
                sub: "tenant-a".into(),
                exp: now_secs() as usize - 100,
                scope: "read".into(),
            },
        );
        assert!(verifier.verify(&token).await.is_none());
    }

    #[tokio::test]
    async fn token_without_scope_accepts() {
        #[derive(serde::Serialize)]
        struct NoScope {
            sub: String,
            exp: usize,
        }
        let verifier = JwtVerifier::new(PUB_PEM).unwrap();
        let token = encode(
            &Header::new(Algorithm::RS256),
            &NoScope {
                sub: "tenant-a".into(),
                exp: now_secs() as usize + 3600,
            },
            &EncodingKey::from_rsa_pem(PRIV_PEM).unwrap(),
        )
        .unwrap();
        let claims = verifier.verify(&token).await.expect("should verify");
        assert_eq!(claims.scope, "");
    }

    #[tokio::test]
    async fn cached_token_rejected_after_exp_passes() {
        let verifier = JwtVerifier::new(PUB_PEM).unwrap().with_leeway(0);
        let token = sign(
            PRIV_PEM,
            &Claims {
                sub: "tenant-a".into(),
                exp: now_secs() as usize + 1,
                scope: "read".into(),
            },
        );
        // First call: exp is still in the future, decodes + caches.
        assert!(verifier.verify(&token).await.is_some());
        // Wait past exp (>= 2s guarantees crossing the second boundary
        // regardless of where `now_secs()` landed within the second the
        // token was minted); cached entry must be re-checked and rejected
        // even though it's well within the 5-minute cache TTL.
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        assert!(verifier.verify(&token).await.is_none());
    }
}
