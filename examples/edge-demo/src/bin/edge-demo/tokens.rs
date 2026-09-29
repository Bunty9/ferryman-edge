//! Mint the JWTs a client would present in `Authorization: Bearer ...`.
//!
//! In production your identity provider does this. The proxy only *verifies*:
//! RS256 signature against `jwks_path`, then `exp`, `nbf`, and (because the
//! config sets them) `iss` and `aud`. The `sub` claim becomes the tenant:
//! the rate-limit key and the `x-ferryman-tenant` header upstream.

use crate::pki::Pki;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// What the proxy config's `[jwt] issuer` / `audience` require.
pub const ISSUER: &str = "https://issuer.demo.local";
pub const AUDIENCE: &str = "ferryman-edge";

/// Knobs for producing good and deliberately bad tokens.
pub struct TokenSpec {
    /// Tenant identity.
    pub sub: String,
    /// Seconds until expiry; negative means already expired.
    pub ttl_secs: i64,
    pub iss: Option<String>,
    pub aud: Option<String>,
    /// Seconds from now until the token becomes valid (`nbf`).
    pub nbf_offset: Option<i64>,
    /// Sign with `jwt-other.key`, which the proxy does not trust.
    pub other_key: bool,
}

impl TokenSpec {
    /// A token the demo proxy accepts.
    pub fn valid(sub: &str) -> Self {
        Self {
            sub: sub.to_string(),
            ttl_secs: 300,
            iss: Some(ISSUER.to_string()),
            aud: Some(AUDIENCE.to_string()),
            nbf_offset: None,
            other_key: false,
        }
    }
}

#[derive(Serialize)]
struct Claims<'a> {
    sub: &'a str,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
}

pub fn mint(pki: &Pki, spec: &TokenSpec) -> anyhow::Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let claims = Claims {
        sub: &spec.sub,
        exp: now + spec.ttl_secs,
        iss: spec.iss.as_deref(),
        aud: spec.aud.as_deref(),
        nbf: spec.nbf_offset.map(|o| now + o),
    };
    let key_file = if spec.other_key {
        "jwt-other.key"
    } else {
        "jwt-signing.key"
    };
    let key = EncodingKey::from_rsa_pem(&std::fs::read(pki.path(key_file))?)?;
    Ok(encode(&Header::new(Algorithm::RS256), &claims, &key)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferryman_edge_core::JwtVerifier;

    /// Verifier configured the way the demo proxy config configures it.
    fn verifier(pki: &Pki) -> JwtVerifier {
        JwtVerifier::new(&std::fs::read(pki.path("jwt-signing.pub")).unwrap())
            .unwrap()
            .with_issuer(ISSUER)
            .with_audience(AUDIENCE)
    }

    #[tokio::test]
    async fn valid_token_verifies_and_bad_variants_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::generate(dir.path()).unwrap();
        let v = verifier(&pki);

        let ok = mint(&pki, &TokenSpec::valid("acme")).unwrap();
        assert_eq!(v.verify(&ok).await.expect("valid token").sub, "acme");

        type Tweak = fn(&mut TokenSpec);
        let variants: [(&str, Tweak); 6] = [
            ("other key", |s| s.other_key = true),
            ("wrong aud", |s| s.aud = Some("someone-else".into())),
            ("wrong iss", |s| s.iss = Some("https://evil".into())),
            ("expired", |s| s.ttl_secs = -120),
            ("not yet valid", |s| s.nbf_offset = Some(600)),
            ("no aud", |s| s.aud = None),
        ];
        for (name, tweak) in variants {
            let mut spec = TokenSpec::valid("acme");
            tweak(&mut spec);
            let t = mint(&pki, &spec).unwrap();
            assert!(v.verify(&t).await.is_none(), "{name} must be rejected");
        }
    }
}
