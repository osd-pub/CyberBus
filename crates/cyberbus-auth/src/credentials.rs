use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const CLAIM: &str = "https://cyberbus.x.aixgg.com/easytier/credentials/v1";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub issuer: String,
    pub subject: String,
    pub product_id: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialClaim {
    pub version: u64,
    pub product_id: String,
    pub credential_epoch: String,
    pub account_seed_secret_hex: String,
    pub max_devices: u64,
    pub virtual_cidr: String,
    pub control_port: u64,
    pub config_version: String,
}
impl CredentialClaim {
    pub fn validate(&self, product: &str) -> Result<u64> {
        let e = &self.credential_epoch;
        if self.version != 1
            || self.product_id != product
            || product.is_empty()
            || e.is_empty()
            || !e.bytes().all(|x| x.is_ascii_digit())
            || (e.len() > 1 && e.starts_with('0'))
            || self.account_seed_secret_hex.len() != 64
            || !self
                .account_seed_secret_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.max_devices != 256
            || self.virtual_cidr != "10.144.0.0/20"
            || self.control_port != 11000
            || self.config_version != "1"
        {
            return Err(Error::InvalidClaims);
        }
        e.parse().map_err(|_| Error::InvalidClaims)
    }
}
/// Network-only secret bundle. Not Clone/Serialize; keep behind the runtime's generation gate.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NetworkMaterial {
    name: String,
    secret: String,
    psk: [u8; 32],
    binding: [u8; 32],
    pub(crate) epoch: u64,
}
impl std::fmt::Debug for NetworkMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkMaterial([REDACTED])")
    }
}
/// Borrow only while the native runtime owns the serialized policy point. Do not log fields.
pub struct NetworkView<'a> {
    pub network_name: &'a str,
    pub network_secret: &'a str,
    pub app_psk: &'a [u8; 32],
    pub binding_id: &'a [u8; 32],
    pub credential_epoch: u64,
    pub config_version: &'static str,
    pub virtual_cidr: &'static str,
    pub control_port: u16,
    pub max_devices: u16,
}
impl std::fmt::Debug for NetworkView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkView([REDACTED])")
    }
}
impl NetworkMaterial {
    pub(crate) fn view(&self) -> NetworkView<'_> {
        NetworkView {
            network_name: &self.name,
            network_secret: &self.secret,
            app_psk: &self.psk,
            binding_id: &self.binding,
            credential_epoch: self.epoch,
            config_version: "1",
            virtual_cidr: "10.144.0.0/20",
            control_port: 11000,
            max_devices: 256,
        }
    }
    pub(crate) fn derive(a: &Account, c: &CredentialClaim) -> Result<Self> {
        let epoch = c.validate(&a.product_id)?;
        let seed = Zeroizing::new(
            hex::decode(&c.account_seed_secret_hex).map_err(|_| Error::InvalidClaims)?,
        );
        let scope = encode(&[
            b"cyberbus/seed/v1",
            a.issuer.as_bytes(),
            a.subject.as_bytes(),
            a.product_id.as_bytes(),
            c.credential_epoch.as_bytes(),
        ]);
        let salt = Sha256::digest(encode(&[b"cyberbus/v1", &scope]));
        let hk = Hkdf::<Sha256>::new(Some(&salt), &seed);
        let mut n = Zeroizing::new([0; 16]);
        let mut s = Zeroizing::new([0; 32]);
        let mut psk = [0; 32];
        let mut binding = [0; 32];
        hk.expand(b"network-name", n.as_mut())
            .map_err(|_| Error::InvalidClaims)?;
        hk.expand(b"network-secret", s.as_mut())
            .map_err(|_| Error::InvalidClaims)?;
        hk.expand(b"app-handshake-psk", &mut psk)
            .map_err(|_| Error::InvalidClaims)?;
        hk.expand(b"session-binding-id/v1", &mut binding)
            .map_err(|_| Error::InvalidClaims)?;
        Ok(Self {
            name: format!("cg-et-mvp-{}", hex::encode(*n)),
            secret: URL_SAFE_NO_PAD.encode(*s),
            psk,
            binding,
            epoch,
        })
    }
    pub(crate) fn tag(&self, a: &Account, key: &[u8; 32]) -> [u8; 32] {
        let mut m = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key length");
        let msg = Zeroizing::new(encode(&[
            b"cyberbus/local-credential-comparison/v1",
            a.issuer.as_bytes(),
            a.subject.as_bytes(),
            a.product_id.as_bytes(),
            self.epoch.to_string().as_bytes(),
            self.name.as_bytes(),
            self.secret.as_bytes(),
            &self.psk,
            &self.binding,
            b"1",
            b"256",
            b"10.144.0.0/20",
            b"11000",
        ]));
        m.update(&msg);
        m.finalize().into_bytes().into()
    }
}
pub(crate) fn encode(fields: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for f in fields {
        v.extend_from_slice(&u32::try_from(f.len()).expect("bounded field").to_be_bytes());
        v.extend_from_slice(f);
    }
    v
}
