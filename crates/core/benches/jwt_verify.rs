//! JWT verifier cache performance benchmark.
//!
//! Measures the speed improvement of cache HIT vs MISS in `JwtVerifier::verify`.
//! Target from PROGRESS.md: cache HIT should be >= 10x faster than MISS.
//!
//! - **HIT**: same verifier, same token, pre-warmed. Calls skip the asymmetric crypto.
//! - **MISS**: fresh verifier per iteration; construction is excluded from timing.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ferryman_edge_core::JwtVerifier;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::time::SystemTime;

const PUB_PEM: &[u8] = include_bytes!("../tests/fixtures/jwt-test-pub.pem");
const PRIV_PEM: &[u8] = include_bytes!("../tests/fixtures/jwt-test-priv.pem");

#[derive(serde::Serialize)]
struct Claims {
    sub: String,
    exp: usize,
    scope: String,
}

fn now_secs() -> usize {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as usize)
        .unwrap_or(0)
}

fn sign_token(sub: &str) -> String {
    let claims = Claims {
        sub: sub.to_string(),
        exp: now_secs() + 3600,
        scope: "read".to_string(),
    };
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(PRIV_PEM).unwrap(),
    )
    .unwrap()
}

fn jwt_verify_bench(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("jwt_verify");

    let owned = sign_token("tenant-a");
    let token = owned.as_str();

    // HIT: one verifier, cache warmed once outside the timed loop.
    let warm = JwtVerifier::new(PUB_PEM).unwrap();
    rt.block_on(warm.verify(token)).expect("token verifies");
    group.bench_function("hit", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(warm.verify(black_box(token)).await) })
    });

    // MISS: a fresh (empty-cache) verifier per iteration, built in the
    // untimed setup, so every timed call pays the RS256 signature check.
    group.bench_function("miss", |b| {
        b.to_async(&rt).iter_batched(
            || JwtVerifier::new(PUB_PEM).unwrap(),
            |v| async move { black_box(v.verify(black_box(token)).await) },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, jwt_verify_bench);
criterion_main!(benches);
