//! Demo PKI: one root CA, a server leaf, a client leaf, an untrusted "rogue"
//! chain, and RSA keys for signing JWTs.
//!
//! Everything is written as PEM files into one directory, because that is
//! exactly how the proxy consumes them (`[tls]` and `[jwt]` in its config).
//! In production these come from your CA and identity provider; the demo
//! only generates them so it can run with no setup.

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const CA_CN: &str = "ferryman-edge demo CA";

/// Handle to a directory of generated key material.
///
/// Files in `dir`:
/// * `ca.crt`, `ca.key`: root CA (the proxy's `client_ca_path`, and what
///   clients trust to verify the proxy)
/// * `server.crt`, `server.key`: proxy leaf, SAN `localhost` + `127.0.0.1`
/// * `client.crt`, `client.key`: client leaf signed by the CA
/// * `rogue-ca.crt`, `rogue-client.crt`, `rogue-client.key`: a chain the
///   proxy does not trust
/// * `jwt-signing.key` (PKCS#8) and `jwt-signing.pub` (SPKI): the issuer's
///   RSA-2048 pair; the proxy's `jwks_path` points at the `.pub`
/// * `jwt-other.key`: an RSA key the proxy does *not* trust
#[derive(Clone, Debug)]
pub struct Pki {
    pub dir: PathBuf,
}

impl Pki {
    /// Open an existing directory produced by [`Pki::generate`].
    pub fn at(dir: &Path) -> anyhow::Result<Pki> {
        let pki = Pki {
            dir: dir.to_path_buf(),
        };
        anyhow::ensure!(
            pki.path("ca.crt").exists(),
            "no PKI in {}: run `edge-demo setup` first",
            dir.display()
        );
        Ok(pki)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Generate a complete fresh PKI into `dir`, overwriting older files.
    pub fn generate(dir: &Path) -> anyhow::Result<Pki> {
        // Private to the owner: the directory holds private keys.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let pki = Pki {
            dir: dir.to_path_buf(),
        };

        let ca_key = KeyPair::generate()?;
        let ca = ca_params(CA_CN).self_signed(&ca_key)?;
        pki.write("ca.crt", &ca.pem())?;
        pki.write_key("ca.key", &ca_key.serialize_pem())?;

        pki.issue_server_leaf(&ca, &ca_key)?;

        let (crt, key) = issue_leaf(
            "demo-client",
            vec![],
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
        )?;
        pki.write("client.crt", &crt)?;
        pki.write_key("client.key", &key)?;

        // A completely separate CA: its client certs must be refused.
        let rogue_key = KeyPair::generate()?;
        let rogue_ca = ca_params("rogue CA").self_signed(&rogue_key)?;
        let (crt, key) = issue_leaf(
            "rogue-client",
            vec![],
            ExtendedKeyUsagePurpose::ClientAuth,
            &rogue_ca,
            &rogue_key,
        )?;
        pki.write("rogue-ca.crt", &rogue_ca.pem())?;
        pki.write("rogue-client.crt", &crt)?;
        pki.write_key("rogue-client.key", &key)?;

        let (private, public) = rsa_pem_pair()?;
        pki.write_key("jwt-signing.key", &private)?;
        pki.write("jwt-signing.pub", &public)?;
        pki.write_key("jwt-other.key", &rsa_pem_pair()?.0)?;
        Ok(pki)
    }

    /// Replace `server.crt`/`server.key` with a fresh leaf from the same CA,
    /// simulating a routine certificate renewal. The proxy picks it up on
    /// SIGUSR1 without dropping connections.
    pub fn rotate_server_cert(&self) -> anyhow::Result<()> {
        let ca_key = KeyPair::from_pem(&std::fs::read_to_string(self.path("ca.key"))?)?;
        // rcgen cannot load a CA certificate back from PEM without an extra
        // feature, so rebuild it: same subject and same key as the CA on
        // disk. A leaf's issuer link is (subject, key), so it chains to the
        // unchanged `ca.crt`.
        let ca = ca_params(CA_CN).self_signed(&ca_key)?;
        self.issue_server_leaf(&ca, &ca_key)
    }

    fn issue_server_leaf(&self, ca: &Certificate, ca_key: &KeyPair) -> anyhow::Result<()> {
        // SANs are what clients verify. Without `127.0.0.1` a client
        // connecting by IP would be refused even with a valid chain.
        let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let (crt, key) = issue_leaf(
            "localhost",
            sans,
            ExtendedKeyUsagePurpose::ServerAuth,
            ca,
            ca_key,
        )?;
        // The demo overwrites the files in place and signals only after both
        // are written. Production renewals should write temp files and
        // `rename` them into place: a reload triggered mid-write (or a crash
        // between the two writes) would otherwise read a new cert with the
        // old key, fail, and leave the proxy on the old material.
        self.write_key("server.key", &key)?;
        self.write("server.crt", &crt)
    }

    fn write(&self, name: &str, contents: &str) -> anyhow::Result<()> {
        std::fs::write(self.path(name), contents)?;
        Ok(())
    }

    /// Private keys are owner-readable only.
    fn write_key(&self, name: &str, contents: &str) -> anyhow::Result<()> {
        let path = self.path(name);
        // Create with 0600 from the start (no window where the key is
        // world-readable); `set_permissions` covers a pre-existing file,
        // whose mode `mode()` does not change.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(contents.as_bytes())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

/// Root CA parameters. Strict verifiers refuse a root that is not marked as
/// a CA (`basicConstraints`) or lacks `keyCertSign`, so set both.
fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid");
    p.distinguished_name.push(DnType::CommonName, cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p
}

/// Issue a leaf, returning `(cert_pem, key_pem)`. The extended key usage pins
/// the leaf to one role: a client cert cannot be used as a server cert.
fn issue_leaf(
    cn: &str,
    sans: Vec<String>,
    eku: ExtendedKeyUsagePurpose,
    ca: &Certificate,
    ca_key: &KeyPair,
) -> anyhow::Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut p = CertificateParams::new(sans)?;
    p.distinguished_name.push(DnType::CommonName, cn);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![eku];
    let cert = p.signed_by(&key, ca, ca_key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// RSA-2048 pair as `(PKCS#8 private PEM, SPKI public PEM)`. rcgen cannot
/// generate RSA keys, so this goes through aws-lc-rs directly.
fn rsa_pem_pair() -> anyhow::Result<(String, String)> {
    let key = RsaKeyPair::generate(KeySize::Rsa2048)?;
    let private: Pkcs8V1Der = key.as_der()?;
    let public: PublicKeyX509Der = key.public_key().as_der()?;
    Ok((
        pem::encode(&pem::Pem::new("PRIVATE KEY", private.as_ref())),
        pem::encode(&pem::Pem::new("PUBLIC KEY", public.as_ref())),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_files_build_an_mtls_server_config() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::generate(dir.path()).unwrap();
        let p = |n: &str| pki.path(n).to_str().unwrap().to_owned();
        ferryman_edge_core::build_mtls_config(&p("server.crt"), &p("server.key"), &p("ca.crt"))
            .expect("proxy accepts the generated material");

        // Rotation keeps the config loadable and changes the cert.
        let before = std::fs::read(pki.path("server.crt")).unwrap();
        pki.rotate_server_cert().unwrap();
        assert_ne!(before, std::fs::read(pki.path("server.crt")).unwrap());
        ferryman_edge_core::build_mtls_config(&p("server.crt"), &p("server.key"), &p("ca.crt"))
            .expect("rotated material loads");
    }
}
