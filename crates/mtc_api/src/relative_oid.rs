use crate::MtcError;
use std::str::FromStr;

/// ASN.1 `RELATIVE OID`.
///
/// TODO upstream this to the `der` crate.
#[derive(Clone)]
pub struct RelativeOid {
    ber: Vec<u8>,
}

impl RelativeOid {
    fn from_arcs(arcs: &[u32]) -> Result<Self, MtcError> {
        let mut ber = Vec::new();
        for arc in arcs {
            for j in (0..=4).rev() {
                #[allow(clippy::cast_possible_truncation)]
                let cur = (arc >> (j * 7)) as u8;

                if cur != 0 || j == 0 {
                    let mut to_write = cur & 0x7f; // lower 7 bits

                    if j != 0 {
                        to_write |= 0x80;
                    }
                    ber.push(to_write);
                }
            }
        }
        if ber.len() > 255 {
            return Err(MtcError::Dynamic("invalid relative OID".into()));
        }
        Ok(Self { ber })
    }

    /// Returns the DER-encoded content bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.ber
    }
}

impl FromStr for RelativeOid {
    type Err = MtcError;
    /// Parse the [`RelativeOid`] from a decimal-dotted string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('.');
        let mut arcs = Vec::new();
        for part in parts {
            let i = part.parse::<u32>()?;
            arcs.push(i);
        }
        Self::from_arcs(&arcs)
    }
}

#[cfg(test)]
mod tests {

    use der::{Any, Encode, Tag};

    use super::*;

    #[test]
    fn encode_decode() {
        let relative_oid = RelativeOid::from_str("13335.2").unwrap();
        let any = Any::new(Tag::RelativeOid, relative_oid.as_bytes()).unwrap();
        assert_eq!(any.to_der().unwrap(), b"\x0d\x03\xe8\x17\x02");
    }
}
