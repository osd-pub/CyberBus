use std::fmt;
use zeroize::Zeroizing;

/// Explicit native integration escape hatch; Debug always redacts and Drop zeroizes.
pub struct SecretBytes(pub(crate) Zeroizing<Vec<u8>>);
impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}
pub(crate) fn random<const N: usize>() -> crate::Result<[u8; N]> {
    let mut b = [0; N];
    getrandom::fill(&mut b).map_err(|_| crate::Error::Unavailable)?;
    Ok(b)
}
